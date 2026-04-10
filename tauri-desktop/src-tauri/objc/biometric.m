// ═══════════════════════════════════════════════════════════════
// FluXlock — macOS Biometric Authentication (Touch ID / Face ID)
// Uses LocalAuthentication.framework + Security.framework via Objective-C
// Exposes C-compatible functions consumed by Rust via FFI
// ═══════════════════════════════════════════════════════════════
//
// References:
//   https://developer.apple.com/documentation/localauthentication/lacontext
//   https://developer.apple.com/documentation/security/restricting-keychain-item-accessibility
//   https://developer.apple.com/documentation/security/secaccesscontrolcreateflags

#import <LocalAuthentication/LocalAuthentication.h>
#import <Security/Security.h>
#include <stdbool.h>
#include <dispatch/dispatch.h>

// ═══════════════════════════════════════════════════════════════
// Biometric availability & type
// ═══════════════════════════════════════════════════════════════

/// Check if biometric authentication hardware is available.
///
/// Strategy (per Apple docs):
///   1. Try LAPolicyDeviceOwnerAuthenticationWithBiometrics (strict biometric-only).
///   2. If that fails, try LAPolicyDeviceOwnerAuthentication (biometric OR passcode).
///      Then inspect biometryType — if it's not "none", biometric HW exists but
///      the strict policy was denied (e.g. unsigned dev build, no entitlements).
///   3. Populate out_error_code so Rust can log the actual LAError code.
bool biometric_is_available_ex(int *out_error_code) {
    LAContext *context = [[LAContext alloc] init];
    NSError *error = nil;

    // First try: strict biometric-only policy
    if ([context canEvaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics error:&error]) {
        if (out_error_code) *out_error_code = 0;
        return true;
    }

    // Save the error code for Rust diagnostics
    int errCode = (int)error.code;
    if (out_error_code) *out_error_code = errCode;

    // Second try: if the strict policy failed, check the fallback policy.
    // On dev builds (unsigned), the strict policy may return biometryNotAvailable (-7)
    // even though Touch ID hardware works fine.
    NSError *fallbackError = nil;
    LAContext *ctx2 = [[LAContext alloc] init];
    if ([ctx2 canEvaluatePolicy:LAPolicyDeviceOwnerAuthentication error:&fallbackError]) {
        // The combined policy succeeded — check if biometric hardware is actually present
        if (ctx2.biometryType != LABiometryTypeNone) {
            if (out_error_code) *out_error_code = 0;
            return true;
        }
    }

    return false;
}

/// Legacy wrapper for backward compat
bool biometric_is_available(void) {
    return biometric_is_available_ex(NULL);
}

/// Get the biometric type available on this machine.
/// Returns: 0 = none, 1 = Touch ID, 2 = Face ID
///
/// Per Apple docs, biometryType is set AFTER calling canEvaluatePolicy,
/// even if the call returns NO (e.g. biometryNotEnrolled still sets the type).
int biometric_get_type(void) {
    LAContext *context = [[LAContext alloc] init];
    NSError *error = nil;

    // We must call canEvaluatePolicy to populate biometryType, even if it fails
    [context canEvaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics error:&error];

    // If strict policy failed, try the fallback to still get biometryType
    if (context.biometryType == LABiometryTypeNone) {
        LAContext *ctx2 = [[LAContext alloc] init];
        [ctx2 canEvaluatePolicy:LAPolicyDeviceOwnerAuthentication error:nil];
        return (int)ctx2.biometryType;
    }

    return (int)context.biometryType;
}

/// Get the LAError code from canEvaluatePolicy for diagnostic logging
int biometric_get_error_code(void) {
    LAContext *context = [[LAContext alloc] init];
    NSError *error = nil;
    if ([context canEvaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics error:&error]) {
        return 0;
    }
    return (int)error.code;
}

// ═══════════════════════════════════════════════════════════════
// Biometric authentication
// ═══════════════════════════════════════════════════════════════

/// Authenticate the user with biometric (shows system Touch ID / Face ID dialog).
///
/// Uses LAPolicyDeviceOwnerAuthentication to allow fallback to system password
/// if biometric-only isn't available (common in unsigned dev builds).
/// This call BLOCKS until the user responds.
bool biometric_authenticate(const char *reason) {
    if (reason == NULL) return false;

    LAContext *context = [[LAContext alloc] init];
    NSError *policyError = nil;

    // Try strict biometric-only first
    LAPolicy policy = LAPolicyDeviceOwnerAuthenticationWithBiometrics;
    if (![context canEvaluatePolicy:policy error:&policyError]) {
        // Fall back to biometric-or-passcode (works on unsigned dev builds)
        policy = LAPolicyDeviceOwnerAuthentication;
        if (![context canEvaluatePolicy:policy error:&policyError]) {
            return false;
        }
    }

    NSString *nsReason = [NSString stringWithUTF8String:reason];
    if (nsReason == nil) return false;

    __block BOOL authSuccess = NO;
    dispatch_semaphore_t semaphore = dispatch_semaphore_create(0);

    [context evaluatePolicy:policy
            localizedReason:nsReason
                      reply:^(BOOL success, NSError * _Nullable __unused error) {
        authSuccess = success;
        dispatch_semaphore_signal(semaphore);
    }];

    dispatch_semaphore_wait(semaphore, DISPATCH_TIME_FOREVER);
    return (bool)authSuccess;
}

// ═══════════════════════════════════════════════════════════════
// Secure Keychain with biometric protection (SecAccessControl)
//
// Per Apple docs (Restricting Keychain Item Accessibility):
//   Use SecAccessControlCreateWithFlags with kSecAccessControlBiometryCurrentSet
//   to require Touch ID / Face ID every time the item is accessed.
//   This stores the key in the Secure Enclave (T2/M1/M2+).
// ═══════════════════════════════════════════════════════════════

static NSString *const kBioKeychainService = @"com.fluxlock.biometric.secureenclave";

/// Store a secret in the Keychain with biometric access control (Secure Enclave).
///
/// The item is protected by:
///   - kSecAttrAccessibleWhenPasscodeSet  → device must have a passcode
///   - kSecAccessControlBiometryCurrentSet → Touch ID required to read;
///     if fingerprints change, item is invalidated (prevents enrollment attacks)
///
/// Returns: 0 = success, negative = OSStatus error
int biometric_keychain_store(const char *account, const void *data, int data_len) {
    if (!account || !data || data_len <= 0) return -1;

    NSString *nsAccount = [NSString stringWithUTF8String:account];
    NSData *nsData = [NSData dataWithBytes:data length:(NSUInteger)data_len];

    // Delete any existing item first (SecItemUpdate doesn't work well with ACLs)
    NSDictionary *deleteQuery = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: kBioKeychainService,
        (__bridge id)kSecAttrAccount: nsAccount,
    };
    SecItemDelete((__bridge CFDictionaryRef)deleteQuery);

    // Create access control: require biometric (current enrollment set)
    CFErrorRef acError = NULL;
    SecAccessControlRef accessControl = SecAccessControlCreateWithFlags(
        kCFAllocatorDefault,
        kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
        kSecAccessControlBiometryCurrentSet,
        &acError
    );

    if (!accessControl || acError) {
        if (accessControl) CFRelease(accessControl);
        return -2;
    }

    NSDictionary *addQuery = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: kBioKeychainService,
        (__bridge id)kSecAttrAccount: nsAccount,
        (__bridge id)kSecValueData: nsData,
        (__bridge id)kSecAttrAccessControl: (__bridge id)accessControl,
    };

    OSStatus status = SecItemAdd((__bridge CFDictionaryRef)addQuery, NULL);
    CFRelease(accessControl);

    return (int)status;
}

/// Retrieve a secret from the biometric-protected Keychain.
///
/// This WILL trigger a Touch ID / Face ID prompt via the system.
/// The `reason` string appears in the biometric dialog.
///
/// Returns: number of bytes copied on success, negative on error.
///   out_data must be pre-allocated by the caller (out_data_capacity bytes).
int biometric_keychain_retrieve(const char *account, const char *reason,
                                void *out_data, int out_data_capacity) {
    if (!account || !out_data || out_data_capacity <= 0) return -1;

    NSString *nsAccount = [NSString stringWithUTF8String:account];

    // Create context with localized reason for the biometric prompt
    LAContext *context = [[LAContext alloc] init];
    if (reason) {
        context.localizedReason = [NSString stringWithUTF8String:reason];
    }

    NSDictionary *query = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: kBioKeychainService,
        (__bridge id)kSecAttrAccount: nsAccount,
        (__bridge id)kSecReturnData: @YES,
        (__bridge id)kSecMatchLimit: (__bridge id)kSecMatchLimitOne,
        (__bridge id)kSecUseAuthenticationContext: context,
    };

    CFTypeRef result = NULL;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);

    if (status != errSecSuccess || !result) {
        return (int)status; // negative OSStatus (e.g. -25293 = errSecAuthFailed)
    }

    NSData *nsData = (__bridge_transfer NSData *)result;
    int len = (int)nsData.length;
    if (len > out_data_capacity) {
        return -3; // buffer too small
    }
    memcpy(out_data, nsData.bytes, (size_t)len);
    return len;
}

/// Delete a biometric-protected Keychain item.
/// Returns: 0 on success, negative OSStatus on error.
int biometric_keychain_delete(const char *account) {
    if (!account) return -1;

    NSString *nsAccount = [NSString stringWithUTF8String:account];
    NSDictionary *query = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: kBioKeychainService,
        (__bridge id)kSecAttrAccount: nsAccount,
    };

    OSStatus status = SecItemDelete((__bridge CFDictionaryRef)query);
    // errSecItemNotFound (-25300) is not an error for delete
    if (status == errSecItemNotFound) return 0;
    return (int)status;
}

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

bool biometric_is_available_ex(int *out_error_code) {
    LAContext *context = [[LAContext alloc] init];
    NSError *error = nil;
    BOOL available = [context canEvaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics error:&error];
    if (out_error_code) *out_error_code = available ? 0 : (int)error.code;
    return available;
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

bool biometric_authenticate(const char *reason) {
    if (reason == NULL) return false;

    LAContext *context = [[LAContext alloc] init];
    NSError *policyError = nil;

    if (![context canEvaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics error:&policyError]) {
        return false;
    }
    context.localizedFallbackTitle = @"";

    NSString *nsReason = [NSString stringWithUTF8String:reason];
    if (nsReason == nil) return false;

    __block BOOL authSuccess = NO;
    dispatch_semaphore_t semaphore = dispatch_semaphore_create(0);

    [context evaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics
            localizedReason:nsReason
                      reply:^(BOOL success, NSError * _Nullable __unused error) {
        authSuccess = success;
        dispatch_semaphore_signal(semaphore);
    }];

    dispatch_semaphore_wait(semaphore, DISPATCH_TIME_FOREVER);
    return (bool)authSuccess;
}

// Use an isolated Data Protection Keychain item protected by the current biometric set.
static NSString *const kBioKeychainService = @"com.fluxlock.biometric.secureenclave";
static NSDictionary *biometricQuery(NSString *account) {
    return @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: kBioKeychainService,
        (__bridge id)kSecAttrAccount: account,
        (__bridge id)kSecUseDataProtectionKeychain: @YES,
    };
}

int biometric_keychain_store(const char *account, const void *data, int data_len) {
    if (!account || !data || data_len <= 0) return errSecParam;
    NSString *name = [NSString stringWithUTF8String:account];
    if (!name) return errSecParam;

    SecAccessControlRef accessControl = SecAccessControlCreateWithFlags(
        kCFAllocatorDefault,
        kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        kSecAccessControlBiometryCurrentSet,
        NULL
    );
    if (!accessControl) return errSecParam;

    NSDictionary *query = biometricQuery(name);
    NSMutableDictionary *item = [query mutableCopy];
    item[(__bridge id)kSecValueData] = [NSData dataWithBytes:data length:(NSUInteger)data_len];
    item[(__bridge id)kSecAttrAccessControl] = (__bridge id)accessControl;

    OSStatus status = SecItemAdd((__bridge CFDictionaryRef)item, NULL);
    if (status == errSecDuplicateItem) {
        status = SecItemDelete((__bridge CFDictionaryRef)query);
        if (status == errSecSuccess || status == errSecItemNotFound) {
            status = SecItemAdd((__bridge CFDictionaryRef)item, NULL);
        }
    }
    CFRelease(accessControl);
    if (status == errSecSuccess) {
        NSMutableDictionary *legacy = [query mutableCopy];
        [legacy removeObjectForKey:(__bridge id)kSecUseDataProtectionKeychain];
        SecItemDelete((__bridge CFDictionaryRef)legacy);
    }
    return status;
}

int biometric_keychain_retrieve(const char *account, const char *reason,
                                void *out_data, int out_data_capacity) {
    if (!account || !reason || !out_data || out_data_capacity <= 0) return errSecParam;
    NSString *name = [NSString stringWithUTF8String:account];
    NSString *prompt = [NSString stringWithUTF8String:reason];
    if (!name || !prompt) return errSecParam;

    LAContext *context = [[LAContext alloc] init];
    context.localizedReason = prompt;
    context.localizedFallbackTitle = @"";

    NSMutableDictionary *query = [biometricQuery(name) mutableCopy];
    query[(__bridge id)kSecUseAuthenticationContext] = context;
    query[(__bridge id)kSecReturnData] = @YES;
    query[(__bridge id)kSecMatchLimit] = (__bridge id)kSecMatchLimitOne;

    CFTypeRef result = NULL;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);
    if (status != errSecSuccess) return status;
    NSData *data = (__bridge_transfer NSData *)result;
    if (data.length == 0 || data.length > (NSUInteger)out_data_capacity) return errSecDecode;
    memcpy(out_data, data.bytes, data.length);
    return (int)data.length;
}

int biometric_keychain_delete(const char *account) {
    if (!account) return errSecParam;
    NSString *name = [NSString stringWithUTF8String:account];
    if (!name) return errSecParam;
    NSDictionary *query = biometricQuery(name);
    OSStatus status = SecItemDelete((__bridge CFDictionaryRef)query);
    NSMutableDictionary *legacy = [query mutableCopy];
    [legacy removeObjectForKey:(__bridge id)kSecUseDataProtectionKeychain];
    SecItemDelete((__bridge CFDictionaryRef)legacy);
    return status == errSecItemNotFound ? errSecSuccess : status;
}

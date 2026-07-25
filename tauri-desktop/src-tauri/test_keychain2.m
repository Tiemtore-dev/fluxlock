#import <Foundation/Foundation.h>
#import <Security/Security.h>

int main() {
    CFErrorRef acError = NULL;
    SecAccessControlRef accessControl = SecAccessControlCreateWithFlags(
        kCFAllocatorDefault,
        kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
        kSecAccessControlBiometryCurrentSet,
        &acError
    );
    
    NSDictionary *addQuery = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: @"testServiceBio",
        (__bridge id)kSecAttrAccount: @"testAccountBio",
        (__bridge id)kSecValueData: [@"test" dataUsingEncoding:NSUTF8StringEncoding],
        (__bridge id)kSecAttrAccessControl: (__bridge id)accessControl,
    };
    OSStatus status = SecItemAdd((__bridge CFDictionaryRef)addQuery, NULL);
    printf("Status: %d\n", (int)status);
    return 0;
}

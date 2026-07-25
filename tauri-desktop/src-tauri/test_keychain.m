#import <Foundation/Foundation.h>
#import <Security/Security.h>

int main() {
    NSDictionary *addQuery = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: @"testService",
        (__bridge id)kSecAttrAccount: @"testAccount",
        (__bridge id)kSecValueData: [@"test" dataUsingEncoding:NSUTF8StringEncoding],
    };
    OSStatus status = SecItemAdd((__bridge CFDictionaryRef)addQuery, NULL);
    printf("Status: %d\n", (int)status);
    return 0;
}

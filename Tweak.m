[*] SDK: /Applications/Xcode_15.4.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS17.5.sdk
[*] clang: /Applications/Xcode_15.4.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/clang
[*] Building LineAccount.dylib ...
/Users/runner/work/lined/lined/Tweak.m:1619:19: warning: format string is not a string literal (potentially insecure) [-Wformat-security]
            NSLog([NSString stringWithFormat:@"[LineAccount] initWithSuiteName IN=%@ -> %@",
                  ^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
/Users/runner/work/lined/lined/Tweak.m:1619:19: note: treat the string as an argument to avoid this
            NSLog([NSString stringWithFormat:@"[LineAccount] initWithSuiteName IN=%@ -> %@",
                  ^
                  @"%@", 
/Users/runner/work/lined/lined/Tweak.m:2604:15: warning: format string is not a string literal (potentially insecure) [-Wformat-security]
        NSLog([NSString stringWithFormat:@"[LineAccount] SWAP rename→copy 退化 OK (errno=%d) %@ -> %@",
              ^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
/Users/runner/work/lined/lined/Tweak.m:2604:15: note: treat the string as an argument to avoid this
        NSLog([NSString stringWithFormat:@"[LineAccount] SWAP rename→copy 退化 OK (errno=%d) %@ -> %@",
              ^
              @"%@", 
/Users/runner/work/lined/lined/Tweak.m:2608:11: warning: format string is not a string literal (potentially insecure) [-Wformat-security]
    NSLog([NSString stringWithFormat:@"[LineAccount] SWAP move FAIL errno=%d copyErr=%@ %@ -> %@",
          ^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
/Users/runner/work/lined/lined/Tweak.m:2608:11: note: treat the string as an argument to avoid this
    NSLog([NSString stringWithFormat:@"[LineAccount] SWAP move FAIL errno=%d copyErr=%@ %@ -> %@",
          ^
          @"%@", 
3 warnings generated.
Undefined symbols for architecture arm64:
  "_la_get_nwconn_hook", referenced from:
      _install_nwconn_got_hook in Tweak-623b2d.o
ld: symbol(s) not found for architecture arm64
clang: error: linker command failed with exit code 1 (use -v to see invocation)
Error: Process completed with exit code 1.

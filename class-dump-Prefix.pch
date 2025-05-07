//
// Prefix header for all source files of the 'class-dump' target in the 'class-dump' project.
//

#ifdef __OBJC__
    #import <Foundation/Foundation.h>
    #import "CDExtensions.h"
    #import "CDClassDump.h"
    #define DLog(format, ...) CFShow((__bridge CFStringRef)[NSString stringWithFormat:format, ## __VA_ARGS__]);
    #define CAUGHT_EXCEPTION_LOG DLog(@"exception caught: %@", exception);
    #define CDLLog(L, format, ...) [CDClassDump logLevel:L stringWithFormat:format, ## __VA_ARGS__]
    #define CDLog(L, format, ...) [CDClassDump logLevel:L string:[NSString stringWithFormat:format, ## __VA_ARGS__]]
    #define VerboseLog(format, ...)CDLog(1,format, ## __VA_ARGS__)
    #define InfoLog(format, ...)CDLog(0,format, ## __VA_ARGS__)
//#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wformat"
    #define OLog(a,b) DLog(@"%@: %016llx (%lu)", a, b, b)
    #define OILog(a,b) InfoLog(@"%@: %016llx (%lu)", a, b, b)
    #define ODLog(a,b) VerboseLog(@"%@: %016llx (%lu)", a, b, b)
//#pragma clang diagnostic pop
    #define ILOG_CMD        InfoLog(@"%s", __PRETTY_FUNCTION__)
    #define VLOG_CMD        VerboseLog(@"%s", __PRETTY_FUNCTION__)
    #define LOG_CMD         DLog(@"%s", __PRETTY_FUNCTION__)
    #define _cmds __PRETTY_FUNCTION__
#endif

// -*- mode: ObjC -*-

//  This file is part of class-dump, a utility for examining the Objective-C segment of Mach-O files.
//  Copyright (C) 1997-2019 Steve Nygard.
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <getopt.h>
#include <stdlib.h>
#include <mach-o/arch.h>

#import "NSString-CDExtensions.h"

#import "CDClassDump.h"
#import "CDFindMethodVisitor.h"
#import "CDClassDumpVisitor.h"
#import "CDMultiFileVisitor.h"
#import "CDFile.h"
#import "CDMachOFile.h"
#import "CDFatFile.h"
#import "CDFatArch.h"
#import "CDSearchPathState.h"

void print_usage(void)
{
    fprintf(stderr,
            "class-dump-c %s\n"
            "Usage: classdumpc [options] <mach-o-file>\n"
            "\n"
            "  where options are:\n"
            "        -a             show instance variable offsets\n"
            "        -A             show implementation addresses\n"
            "        --arch <arch>  choose a specific architecture from a universal binary (ppc, ppc64, i386, x86_64, armv6, armv7, armv7s, arm64)\n"
            "        -C <regex>     only display classes matching regular expression\n"
            "        -f <str>       find string in method name\n"
            "        -H             generate header files in current directory, or directory specified with -o\n"
            "        -I             sort classes, categories, and protocols by inheritance (overrides -s)\n"
            "        -o <dir>       output directory used for -H\n"
            "        -r             recursively expand frameworks and fixed VM shared libraries\n"
            "        -s             sort classes and categories by name\n"
            "        -S             sort methods by name\n"
            "        -t             suppress header in output, for testing\n"
            "        -e             dump the entitlements\n"
            "        --list-arches  list the arches in the file, then exit\n"
            "        --sdk-ios      specify iOS SDK version (will look for /Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS<version>.sdk\n"
            "                       or /Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS<version>.sdk)\n"
            "        --sdk-mac      specify Mac OS X version (will look for /Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX<version>.sdk\n"
            "                       or /Developer/SDKs/MacOSX<version>.sdk)\n"
            "        --sdk-root     specify the full SDK root path (or use --sdk-ios/--sdk-mac for a shortcut)\n"
            ,
            CLASS_DUMP_VERSION
       );
}

#define CD_OPT_ARCH        1
#define CD_OPT_LIST_ARCHES 2
#define CD_OPT_VERSION     3
#define CD_OPT_SDK_IOS     4
#define CD_OPT_SDK_MAC     5
#define CD_OPT_SDK_ROOT    6
#define CD_OPT_HIDE        7

int main(int argc, char *argv[])
{
    @autoreleasepool {
        NSString *searchString;
        BOOL shouldGenerateSeparateHeaders = NO;
        BOOL shouldListArches = NO;
        BOOL shouldPrintVersion = NO;
        CDArch targetArch;
        BOOL hasSpecifiedArch = NO;
        BOOL suppressAllHeaderOutput = NO;
        BOOL dumpEnt = NO; //whether or not to dump entitlements
        BOOL shallow = NO; //whether to skip protocols and categories, for testing
        NSString *outputPath;
        NSMutableSet *hiddenSections = [NSMutableSet set];

        int ch;
        BOOL errorFlag = NO;

        struct option longopts[] = {
            { "show-ivar-offsets",       no_argument,       NULL, 'a' },
            { "show-imp-addr",           no_argument,       NULL, 'A' },
            { "match",                   required_argument, NULL, 'C' },
            { "find",                    required_argument, NULL, 'f' },
            { "generate-multiple-files", no_argument,       NULL, 'H' },
            { "sort-by-inheritance",     no_argument,       NULL, 'I' },
            { "output-dir",              required_argument, NULL, 'o' },
            { "recursive",               no_argument,       NULL, 'r' },
            { "sort",                    no_argument,       NULL, 's' },
            { "sort-methods",            no_argument,       NULL, 'S' },
            { "arch",                    required_argument, NULL, CD_OPT_ARCH },
            { "list-arches",             no_argument,       NULL, CD_OPT_LIST_ARCHES },
            { "suppress-header",         no_argument,       NULL, 't' },
            { "version",                 no_argument,       NULL, CD_OPT_VERSION },
            { "sdk-ios",                 required_argument, NULL, CD_OPT_SDK_IOS },
            { "sdk-mac",                 required_argument, NULL, CD_OPT_SDK_MAC },
            { "sdk-root",                required_argument, NULL, CD_OPT_SDK_ROOT },
            { "hide",                    required_argument, NULL, CD_OPT_HIDE },
            { "entitlements",            no_argument,       NULL, 'e' },
            { "debug",                   no_argument,       NULL, 'd'},
            { "verbose",                 no_argument,       NULL, 'v'},
            { "fixups",                  no_argument,       NULL, 'F'},
            { "silent",                  no_argument,       NULL, 'x'},
            { "preprocessor-exit",       no_argument,       NULL, 'z'},
            { "shallow",                 no_argument,       NULL, 'h'},
            { NULL,                      0,                 NULL, 0 },
        };

        if (argc == 1) {
            print_usage();
            exit(0);
        }
        [[NSUserDefaults standardUserDefaults] removeObjectForKey:@"verbose"]; //reset it every time
        [[NSUserDefaults standardUserDefaults] removeObjectForKey:@"debug"];
#ifdef DEBUG
        [[NSUserDefaults standardUserDefaults] setBool:TRUE forKey:@"debug"];
        [[NSUserDefaults standardUserDefaults] setBool:TRUE forKey:@"verbose"]; //make it easier to avoid hardcoded macros to enable logging
#endif
        CDClassDump *classDump = [[CDClassDump alloc] init];

        while ( (ch = getopt_long(argc, argv, "aAC:f:HIo:rRsStvFxdzhe", longopts, NULL)) != -1) {
            switch (ch) {
                case CD_OPT_ARCH: {
                    NSString *name = [NSString stringWithUTF8String:optarg];
                    targetArch = CDArchFromName(name);
                    if (targetArch.cputype != CPU_TYPE_ANY)
                        hasSpecifiedArch = YES;
                    else {
                        fprintf(stderr, "Error: Unknown arch %s\n\n", optarg);
                        errorFlag = YES;
                    }
                    break;
                }
                    
                case CD_OPT_LIST_ARCHES:
                    shouldListArches = YES;
                    break;
                    
                case CD_OPT_VERSION:
                    shouldPrintVersion = YES;
                    break;
                    
                case CD_OPT_SDK_IOS: {
                    NSString *root = [NSString stringWithUTF8String:optarg];
                    //DLog(@"root: %@", root);
                    NSString *str;
                    if ([[NSFileManager defaultManager] fileExistsAtPath: @"/Applications/Xcode.app"]) {
                        str = [NSString stringWithFormat:@"/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS%@.sdk", root];
                    } else if ([[NSFileManager defaultManager] fileExistsAtPath: @"/Developer"]) {
                        str = [NSString stringWithFormat:@"/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS%@.sdk", root];
                    }
                    classDump.sdkRoot = str;
                    
                    break;
                }
                    
                case CD_OPT_SDK_MAC: {
                    NSString *root = [NSString stringWithUTF8String:optarg];
                    //DLog(@"root: %@", root);
                    NSString *str;
                    if ([[NSFileManager defaultManager] fileExistsAtPath: @"/Applications/Xcode.app"]) {
                        str = [NSString stringWithFormat:@"/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX%@.sdk", root];
                    } else if ([[NSFileManager defaultManager] fileExistsAtPath: @"/Developer"]) {
                        str = [NSString stringWithFormat:@"/Developer/SDKs/MacOSX%@.sdk", root];
                    }
                    classDump.sdkRoot = str;
                    
                    break;
                }
                    
                case CD_OPT_SDK_ROOT: {
                    NSString *root = [NSString stringWithUTF8String:optarg];
                    //DLog(@"root: %@", root);
                    classDump.sdkRoot = root;
                    
                    break;
                }
                    
                case CD_OPT_HIDE: {
                    NSString *str = [NSString stringWithUTF8String:optarg];
                    if ([str isEqualToString:@"all"]) {
                        [hiddenSections addObject:@"structures"];
                        [hiddenSections addObject:@"protocols"];
                    } else {
                        [hiddenSections addObject:str];
                    }
                    break;
                }
                    
                case 'e':
                    dumpEnt = true;
                    classDump.dumpEntitlements = true;
                    break;
                    
                case 'h':
                    shallow = true;
                    classDump.shallow = true;
                    VerboseLog(@"SHALLOW");
                    break;
                    
                case 'z':
                    classDump.stopAfterPreProcessor = true;
                    break;
                case 'd':
                    [[NSUserDefaults standardUserDefaults] setBool:TRUE forKey:@"debug"];
                    break;
                case 'F':
                    break;
                case 'x':
                    suppressAllHeaderOutput = YES;
                    break;
                case 'v':
                    [[NSUserDefaults standardUserDefaults] setBool:TRUE forKey:@"verbose"];
                    classDump.verbose = YES;
                    break;
                    
                case 'a':
                    classDump.shouldShowIvarOffsets = YES;
                    break;
                    
                case 'A':
                    classDump.shouldShowMethodAddresses = YES;
                    break;
                    
                case 'C': {
                    NSError *error;
                    NSRegularExpression *regularExpression = [NSRegularExpression regularExpressionWithPattern:[NSString stringWithUTF8String:optarg]
                                                                                                       options:(NSRegularExpressionOptions)0
                                                                                                         error:&error];
                    if (regularExpression != nil) {
                        classDump.regularExpression = regularExpression;
                    } else {
                        fprintf(stderr, "class-dump: Error with regular expression: %s\n\n", [[error localizedFailureReason] UTF8String]);
                        errorFlag = YES;
                    }

                    // Last one wins now.
                    break;
                }
                    
                case 'f': {
                    searchString = [NSString stringWithUTF8String:optarg];
                    break;
                }
                    
                case 'H':
                    shouldGenerateSeparateHeaders = YES;
                    break;
                    
                case 'I':
                    classDump.shouldSortClassesByInheritance = YES;
                    break;
                    
                case 'o':
                    outputPath = [NSString stringWithUTF8String:optarg];
                    break;
                    
                case 'r':
                    classDump.shouldProcessRecursively = YES;
                    break;
                    
                case 's':
                    classDump.shouldSortClasses = YES;
                    break;
                    
                case 'S':
                    classDump.shouldSortMethods = YES;
                    break;
                    
                case 't':
                    classDump.shouldShowHeader = NO;
                    break;
                    
                case '?':
                default:
                    errorFlag = YES;
                    break;
            }
        }

        if (errorFlag) {
            print_usage();
            exit(2);
        }

        if (shouldPrintVersion) {
            printf("class-dump %s compiled %s\n", CLASS_DUMP_VERSION, __DATE__ " " __TIME__);
            exit(0);
        }

        if (optind < argc) {
            NSString *arg = [NSString stringWithFileSystemRepresentation:argv[optind]];
            NSString *executablePath = [arg executablePathForFilename];
            if (shouldListArches) {
                if (executablePath == nil) {
                    printf("none\n");
                } else {
                    CDSearchPathState *searchPathState = [[CDSearchPathState alloc] init];
                    searchPathState.executablePath = executablePath;
                    id macho = [CDFile fileWithContentsOfFile:executablePath searchPathState:searchPathState];
                    if (macho == nil) {
                        printf("none\n");
                    } else {
                        if ([macho isKindOfClass:[CDMachOFile class]]) {
                            printf("%s\n", [[macho archName] UTF8String]);
                        } else if ([macho isKindOfClass:[CDFatFile class]]) {
                            printf("%s\n", [[[macho archNames] componentsJoinedByString:@" "] UTF8String]);
                        }
                    }
                }
            } else {
                if (executablePath == nil) {
                    fprintf(stderr, "class-dump: Input file (%s) doesn't contain an executable.\n", [arg fileSystemRepresentation]);
                    exit(1);
                }

                classDump.searchPathState.executablePath = [executablePath stringByDeletingLastPathComponent];
                CDFile *file = [CDFile fileWithContentsOfFile:executablePath searchPathState:classDump.searchPathState];
                if (file == nil) {
                    NSFileManager *defaultManager = [NSFileManager defaultManager];
                    
                    if ([defaultManager fileExistsAtPath:executablePath]) {
                        if ([defaultManager isReadableFileAtPath:executablePath]) {
                            fprintf(stderr, "class-dump: Input file (%s) is neither a Mach-O file nor a fat archive.\n", [executablePath UTF8String]);
                        } else {
                            fprintf(stderr, "class-dump: Input file (%s) is not readable (check read permissions).\n", [executablePath UTF8String]);
                        }
                    } else {
                        fprintf(stderr, "class-dump: Input file (%s) does not exist.\n", [executablePath UTF8String]);
                    }

                    exit(1);
                }

                if (hasSpecifiedArch == NO) {
                    if ([file bestMatchForLocalArch:&targetArch] == NO) {
                        fprintf(stderr, "Error: Couldn't get local architecture\n");
                        exit(1);
                    }
                    //DLog(@"No arch specified, best match for local arch is: (%08x, %08x)", targetArch.cputype, targetArch.cpusubtype);
                } else {
                    //DLog(@"chosen arch is: (%08x, %08x)", targetArch.cputype, targetArch.cpusubtype);
                }
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wconditional-uninitialized"
                //only doing the above because i know in this instance it will be initialized
                classDump.targetArch = targetArch;
#pragma clang diagnostic pop
                classDump.searchPathState.executablePath = [executablePath stringByDeletingLastPathComponent];

                NSError *error;
                if (![classDump loadFile:file error:&error]) {
                    fprintf(stderr, "Error: %s\n", [[error localizedFailureReason] UTF8String]);
                    exit(1);
                } else {
                    [classDump processObjectiveCData];
                    [classDump registerTypes];
                    
                    if (searchString != nil) {
                        CDFindMethodVisitor *visitor = [[CDFindMethodVisitor alloc] init];
                        visitor.classDump = classDump;
                        visitor.searchString = searchString;
                        [classDump recursivelyVisit:visitor];
                    } else if (shouldGenerateSeparateHeaders) {
                        CDMultiFileVisitor *multiFileVisitor = [[CDMultiFileVisitor alloc] init];
                        multiFileVisitor.classDump = classDump;
                        classDump.typeController.delegate = multiFileVisitor;
                        multiFileVisitor.outputPath = outputPath;
                        [classDump recursivelyVisit:multiFileVisitor];
                        if (dumpEnt) {
                            NSString *newName = [[[[executablePath lastPathComponent] stringByDeletingPathExtension] stringByAppendingString:@"-Entitlements"] stringByAppendingPathExtension:@"plist"];
                            NSString *entPath = [outputPath stringByAppendingPathComponent:newName];
                            NSDictionary *ent = [[classDump.machOFiles firstObject] entitlementsDictionary];
                            if (ent){
                                InfoLog(@"writing entitlements to path: %@", entPath);
                                [ent writeToFile:entPath atomically:true];
                            }
                        }
                    } else {
                        if (suppressAllHeaderOutput){
                            exit(0);
                        }
                        CDClassDumpVisitor *visitor = [[CDClassDumpVisitor alloc] init];
                        visitor.classDump = classDump;
                        if ([hiddenSections containsObject:@"structures"]) visitor.shouldShowStructureSection = NO;
                        if ([hiddenSections containsObject:@"protocols"])  visitor.shouldShowProtocolSection  = NO;
                        [classDump recursivelyVisit:visitor];
                        if (dumpEnt) {
                            NSString *ent = [[classDump.machOFiles firstObject] entitlements];
                            DLog(@"%@", ent);
                        }
                    }
                }
            }
        }
        exit(0); // avoid costly autorelease pool drain, we’re exiting anyway
    }
}

#include <windows.h>
#include <stdint.h>
#include <stdio.h>

#define OPT_MAX_STRING 256

#define OPT_TYPE_NONE   1
#define OPT_TYPE_STRING 2
#define OPT_TYPE_DEC    3
#define OPT_TYPE_HEX    4
#define OPT_TYPE_FLAG   5
#define OPT_TYPE_DEC64  6
#define OPT_TYPE_HEX64  7

// structure to hold data of any type
typedef union _opt_arg_t {
    int flag;

    int8_t s8;
    uint8_t u8;
    int8_t* s8_ptr;
    uint8_t* u8_ptr;

    int16_t s16;
    uint16_t u16;
    int16_t* s16_ptr;
    uint16_t* u16_ptr;

    int32_t s32;
    uint32_t u32;
    int32_t* s32_ptr;
    uint32_t* u32_ptr;

    int64_t s64;
    uint64_t u64;
    int64_t* s64_ptr;
    uint64_t* u64_ptr;

    void* ptr;
    char str[OPT_MAX_STRING + 1];
} opt_arg;

typedef int (*void_callback_t)(void);         // execute callback with no return value or argument
typedef int (*arg_callback_t)(opt_arg*, void*); // process argument, optionally store in optarg

static int get_opt(
    int argc,         // total number of elements in argv
    char* argv[],     // argument array
    int arg_type,     // type of argument expected (none, flag, decimal, hexadecimal, string)
    void* output,     // pointer to variable that stores argument
    char* short_opt,  // short form of option. e.g: -a
    char* long_opt,   // long form of option. e.g: --arch
    void* callback)   // callback function to process argument
{
    int  valid = 0, i, req = 0, opt_len, opt_type;
    char* args = NULL, * opt = NULL, * arg = NULL, * tmp = NULL;
    opt_arg* optarg = (opt_arg*)output;
    void_callback_t void_cb;
    arg_callback_t  arg_cb;

    // perform some basic validation
    if (argc <= 1) return 0;
    if (argv == NULL) return 0;

    if (arg_type != OPT_TYPE_NONE &&
        arg_type != OPT_TYPE_STRING &&
        arg_type != OPT_TYPE_DEC &&
        arg_type != OPT_TYPE_HEX &&
        arg_type != OPT_TYPE_HEX64 &&
        arg_type != OPT_TYPE_FLAG) return 0;

    /*printf("Arg type for %s, %s : %s",
        short_opt != NULL ? short_opt : "N/A",
        long_opt != NULL ? long_opt : "N/A",
        arg_type == OPT_TYPE_NONE ? "None" :
        arg_type == OPT_TYPE_STRING ? "String" :
        arg_type == OPT_TYPE_DEC ? "Decimal" :
        arg_type == OPT_TYPE_HEX ? "Hexadecimal" :
        arg_type == OPT_TYPE_FLAG ? "Flag" : "Unknown");*/

    // for each argument in array
    for (i = 1; i < argc && !valid; i++) {
        // set the current argument to examine
        arg = argv[i];
        // if it doesn't contain a switch, skip it
        if (*arg != '-') continue;
        // we have a switch. initially, we assume short form
        arg++;
        opt_type = 0;
        // long form? skip one more and change the option type
        if (*arg == '-') {
            arg++;
            opt_type++;
        }

        // is an argument required by the user?
        req = ((arg_type != OPT_TYPE_NONE) && (arg_type != OPT_TYPE_FLAG));
        // use short or long form for current argument being examined
        opt = (opt_type) ? long_opt : short_opt;
        // if no form provided by user for current argument, skip it
        if (opt == NULL) continue;
        // copy string to dynamic buffer
        opt_len = strlen(opt);
        if (opt_len == 0) continue;

        tmp = (char*)calloc(sizeof(uint8_t), opt_len + 1);
        if (tmp == NULL) {
            //printf("Unable to allocate memory for %s.\n", opt);
            continue;
        }
        else {
            strcpy(tmp, opt);
        }
        // tokenize the string.
        opt = strtok(tmp, ";");
        // while we have options
        while (opt != NULL && !valid) {
            // get the length
            opt_len = strlen(opt);
            // do we have a match?   
            if (!strncmp(opt, arg, opt_len)) {
                //
                // at this point, we have a valid matching argument
                // if something fails from here on in, return invalid
                // 
                // skip the option
                arg += opt_len;
                // an argument is *not* required
                if (!req) {
                    // so is the next byte non-zero? return invalid
                    if (*arg != 0) return 0;
                }
                else {
                    // an argument is required
                    // if the next byte is a colon or assignment operator, skip it.
                    if (*arg == ':' || *arg == '=') arg++;

                    // if the next byte is zero
                    if (*arg == 0) {
                        // and no arguments left. return invalid
                        if ((i + 1) >= argc) return 0;
                        args = argv[i + 1];
                    }
                    else {
                        args = arg;
                    }
                }
                // end loop
                valid = 1;
                break;
            }
            opt = strtok(NULL, ";");
        }
        if (tmp != NULL) free(tmp);
    }

    // if valid option found
    if (valid) {
        //printf("Found match");
        // ..and a callback exists
        if (callback != NULL) {
            // if we have a parameter
            if (args != NULL) {
                //printf("Executing callback with %s.", args);
                // execute with parameter
                arg_cb = (arg_callback_t)callback;
                int result = arg_cb(optarg, args);
                if (result == 0) {
                    printf("-%s parameter Parsing Error!", short_opt);
                    exit(0);
                }
            }
            else {
                //printf("Executing callback.");
                // otherwise, execute without
                void_cb = (void_callback_t)callback;
                int result = void_cb();
                if (result == 0) {
                    printf("-%s parameter Parsing Error!", short_opt);
                    exit(0);
                }
            }
        }
        else {
            // there's no callback, try process ourselves
            if (args != NULL) {
                //printf("Parsing %s\n", args);
                switch (arg_type) {
                case OPT_TYPE_DEC:
                case OPT_TYPE_HEX:
                    //printf("Converting %s to 32-bit binary", args);
                    optarg->u32 = strtoul(args, NULL, arg_type == OPT_TYPE_DEC ? 10 : 16);
                    break;
                case OPT_TYPE_DEC64:
                case OPT_TYPE_HEX64:
                    //printf("Converting %s to 64-bit binary", args);
                    optarg->u64 = strtoull(args, NULL, arg_type == OPT_TYPE_DEC64 ? 10 : 16);
                    break;
                case OPT_TYPE_STRING:
                    //printf("Copying %s to output", args);
                    strncpy(optarg->str, args, OPT_MAX_STRING);
                    break;
                }
            }
            else {
                // there's no argument, just set the flag
                //printf("Setting flag");
                optarg->flag = 1;
            }
        }
    }
    // return result
    return valid;
}
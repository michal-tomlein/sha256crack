/*
 * Copyright (c) 2010, Michal Tomlein
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 *     1. Redistributions of source code must retain the above copyright notice,
 *        this list of conditions and the following disclaimer.
 *     2. Redistributions in binary form must reproduce the above copyright notice,
 *        this list of conditions and the following disclaimer in the documentation
 *        and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
 * ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <assert.h>
#include <math.h>
#ifdef __APPLE__
#include <OpenCL/opencl.h>
#else
#include <CL/opencl.h>
#endif

#include "sha256.h"
#include "sha256.cl.h"

#define DEFAULT_HASH "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
#define DEFAULT_CHARSET "abcdefghijklmnopqrstuvwxyz"
#define DEFAULT_MIN_LENGTH 3
#define DEFAULT_MAX_LENGTH 5
#define DEFAULT_CHUNK_SIZE 1000000

void help() {
    printf("Usage: sha256crack [options] [hash]\n");
    printf("Options:\n");
    printf("  -h, --help             Display this information\n");
    printf("  -H, --host             Run without OpenCL\n");
    printf("  -C, --cpu              Run with OpenCL, device CPU\n");
    printf("  -G, --gpu (default)    Run with OpenCL, device GPU\n");
    printf("  -d DEV, --device DEV   Run with OpenCL, device DEV\n");
    printf("                         Permissible devices include:\n");
    printf("                         0 - no device, equivalent to --host\n");
    printf("                         1 - CPU\n");
    printf("                         2 - GPU (default)\n");
    printf("                         4 - Accelerator\n");
    printf("  -i I, --min-length I   Minimum password length, defaults to %d\n",
           DEFAULT_MIN_LENGTH);
    printf("  -a A, --max-length A   Maximum password length, defaults to %d\n",
           DEFAULT_MAX_LENGTH);
    printf("  -c SET, --charset SET  Password character set, defaults to\n");
    printf("                         %s\n", DEFAULT_CHARSET);
    printf("  -k S, --chunk-size S   OpenCL chunk size, defaults to %d\n",
           DEFAULT_CHUNK_SIZE);
    printf("                         Pass 0 to prevent splitting into chunks\n");
    printf("  -s, --silent           Do not print verbose information\n");
}

int main (int argc, const char * argv[]) {
    int host = 0;
    int device = CL_DEVICE_TYPE_GPU;
    char hash[65];
    char * character_set = DEFAULT_CHARSET;
    cl_uint min_length = DEFAULT_MIN_LENGTH;
    cl_uint max_length = DEFAULT_MAX_LENGTH;
    size_t chunk_size = DEFAULT_CHUNK_SIZE;
    int silent = 0;

    int opt;
    int option_index = 0;

    static struct option long_options[] = {
        { "help",       no_argument,       0, 'h' },
        { "host",       no_argument,       0, 'H' },
        { "cpu",        no_argument,       0, 'C' },
        { "gpu",        no_argument,       0, 'G' },
        { "device",     required_argument, 0, 'd' },
        { "min-length", required_argument, 0, 'i' },
        { "max-length", required_argument, 0, 'a' },
        { "charset",    required_argument, 0, 'c' },
        { "chunk-size", required_argument, 0, 'k' },
        { "silent",     no_argument,       0, 's' },
        { 0, 0, 0, 0 }
    };

    while ((opt = getopt_long(argc, (char * const *)argv, "hHCGd:i:a:c:k:s",
                              long_options, &option_index)) != -1) {
        switch (opt) {
            case 'h':
                help();
                exit(EXIT_SUCCESS);
                break;

            case 'H':
                host = 1;
                break;

            case 'C':
                device = CL_DEVICE_TYPE_CPU;
                break;

            case 'G':
                device = CL_DEVICE_TYPE_GPU;
                break;

            case 'd':
                device = atoi(optarg);
                break;

            case 'i':
                min_length = atoi(optarg);
                break;

            case 'a':
                max_length = atoi(optarg);
                break;

            case 'c':
                character_set = (char *)malloc((strlen(optarg) + 1) * sizeof(char));
                strcpy(character_set, optarg);
                break;

            case 'k':
                chunk_size = atoi(optarg);
                break;

            case 's':
                silent = 1;
                break;

            case '?':
            default:
                exit(EXIT_FAILURE);
        }
    }

    argc -= optind;
    argv += optind;

    if (argc > 0 && strlen(argv[0]) == 64) {
        strncpy(hash, argv[0], 64);
        hash[64] = '\0';
    } else {
        strcpy(hash, DEFAULT_HASH);
    }

    if (!silent) {
        printf("--> Hash: %s\n", hash);
        printf("--> Minimum length: %d, Maximum length: %d\n", min_length, max_length);
        printf("--> Character set: %s\n", character_set);
    }

    if (min_length > max_length)
        min_length = max_length;

    if (host || !device) {
        if (!silent)
            printf("--> Running on host\n");

        char * result = reverse_sha256(hash, min_length, max_length, character_set);
        if (!silent)
            printf("Result: %s\n", result ? result : "No match.");
        else if (result)
            printf("%s\n", result);
        if (result)
            free(result);
    }

    if (device && !host) {
        if (!silent) {
            if (chunk_size)
                printf("--> Chunk size: %zu\n", chunk_size);
            printf("--> Running on device: ");
            switch (device) {
                case CL_DEVICE_TYPE_CPU: printf("CPU"); break;
                case CL_DEVICE_TYPE_GPU: printf("GPU"); break;
                case CL_DEVICE_TYPE_ACCELERATOR: printf("Accelerator"); break;
                case CL_DEVICE_TYPE_ALL: printf("Any"); break;
            }
            printf("\n");
        }

        cl_uint character_set_length = strlen(character_set);
        cl_int err;
        cl_device_id devices;
        cl_context context;
        cl_command_queue queue;
        cl_program program[1];
        cl_kernel kernel[1];

        err = clGetDeviceIDs(NULL, device, 1, &devices, NULL);
        assert(err == CL_SUCCESS);

        context = clCreateContext(0, 1, &devices, NULL, NULL, &err);
        assert(err == CL_SUCCESS);

        queue = clCreateCommandQueue(context, devices, 0, NULL);

        program[0] = clCreateProgramWithSource(context, 1, (const char **)&program_source, NULL, &err);
        assert(err == CL_SUCCESS);

        err = clBuildProgram(program[0], 0, NULL, NULL, NULL, NULL);
        assert(err == CL_SUCCESS);

        kernel[0] = clCreateKernel(program[0], "reverse_sha256", &err);
        assert(err == CL_SUCCESS);

        cl_mem hash_mem = clCreateBuffer(context, CL_MEM_READ_ONLY, 65, NULL, &err);
        assert(err == CL_SUCCESS);

        err = clEnqueueWriteBuffer(queue, hash_mem, CL_FALSE, 0, 65, hash, 0, NULL, NULL);
        assert(err == CL_SUCCESS);

        cl_mem charset_mem = clCreateBuffer(context, CL_MEM_READ_ONLY, character_set_length, NULL, &err);
        assert(err == CL_SUCCESS);

        err = clEnqueueWriteBuffer(queue, charset_mem, CL_FALSE, 0, character_set_length, character_set, 0, NULL, NULL);
        assert(err == CL_SUCCESS);

        cl_mem output_mem = clCreateBuffer(context, CL_MEM_WRITE_ONLY, 32, NULL, &err);
        assert(err == CL_SUCCESS);

        err = clFinish(queue);
        assert(err == CL_SUCCESS);

        if (min_length > 32)
            min_length = 32;
        if (max_length > 32)
            max_length = 32;

        clSetKernelArg(kernel[0], 0, sizeof(cl_mem), &hash_mem);
        clSetKernelArg(kernel[0], 1, sizeof(cl_uint), &min_length);
        clSetKernelArg(kernel[0], 2, sizeof(cl_uint), &max_length);
        clSetKernelArg(kernel[0], 3, sizeof(cl_mem), &charset_mem);
        clSetKernelArg(kernel[0], 4, sizeof(cl_uint), &character_set_length);
        clSetKernelArg(kernel[0], 6, sizeof(cl_mem), &output_mem);

        size_t total_work_size = pow(character_set_length, max_length);
        size_t chunk_count = 1;
        if (chunk_size)
            chunk_count = ceil(pow(character_set_length, max_length) / (double)chunk_size);
        size_t global_work_size[1];

        char output[33];
        output[0] = '\0';
        output[32] = '\0';

        cl_uint offset = 0;
        for (int i = 0; !output[0] && i < chunk_count; ++i, offset += chunk_size) {
            clSetKernelArg(kernel[0], 5, sizeof(cl_uint), &offset);

            global_work_size[0] = chunk_size < total_work_size - offset && chunk_size ?
                                  chunk_size : total_work_size - offset;

            err = clEnqueueNDRangeKernel(queue, kernel[0], 1, NULL, global_work_size, NULL, 0, NULL, NULL);
            assert(err == CL_SUCCESS);

            err = clFinish(queue);
            assert(err == CL_SUCCESS);

            err = clEnqueueReadBuffer(queue, output_mem, CL_TRUE, 0, 32, output, 0, NULL, NULL);
            assert(err == CL_SUCCESS);
        }

        if (!silent)
            printf("Result: %s\n", output[0] ? output : "No match.");
        else if (output[0])
            printf("%s\n", output);

        clReleaseMemObject(hash_mem);
        clReleaseMemObject(charset_mem);
        clReleaseMemObject(output_mem);
        clReleaseProgram(program[0]);
        clReleaseKernel(kernel[0]);
        clReleaseCommandQueue(queue);
        clReleaseContext(context);
    }

    return 0;
}

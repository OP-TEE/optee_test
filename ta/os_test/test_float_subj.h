/*
 * Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef TEST_FLOAT_SUBJ_H
#define TEST_FLOAT_SUBJ_H

double test_float_dadd(double a, double b);
double test_float_ddiv(double a, double b);
double test_float_dmul(double a, double b);
double test_float_drsub(double a, double b);
double test_float_dsub(double a, double b);
int test_float_dcmpeq(double a, double b);
int test_float_dcmplt(double a, double b);
int test_float_dcmple(double a, double b);
int test_float_dcmpge(double a, double b);
int test_float_dcmpgt(double a, double b);
float test_float_fadd(float a, float b);
float test_float_fdiv(float a, float b);
float test_float_fmul(float a, float b);
float test_float_frsub(float a, float b);
float test_float_fsub(float a, float b);
int test_float_fcmpeq(float a, float b);
int test_float_fcmplt(float a, float b);
int test_float_fcmple(float a, float b);
int test_float_fcmpge(float a, float b);
int test_float_fcmpgt(float a, float b);
int test_float_d2iz(double a);
unsigned test_float_d2uiz(double a);
long long test_float_d2lz(double a);
unsigned long long test_float_d2ulz(double a);
int test_float_f2iz(float a);
unsigned test_float_f2uiz(float a);
long long test_float_f2lz(float a);
unsigned long long test_float_f2ulz(float a);
float test_float_d2f(double a);
double test_float_f2d(float a);
double test_float_i2d(int a);
double test_float_ui2d(unsigned a);
double test_float_l2d(long long a);
double test_float_ul2d(unsigned long long a);
float test_float_i2f(int a);
float test_float_ui2f(unsigned a);
float test_float_l2f(long long a);
float test_float_ul2f(unsigned long long a);

#endif /*TEST_FLOAT_SUBJ_H*/

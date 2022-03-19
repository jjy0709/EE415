#include <stdint.h>
#define FP (1<<14)

int to_fp(int n){
    return n*FP;
};

int to_int(int x){
    return x/FP;
};

int to_int_round(int x){
    if (x>=0) return (x+FP/2)/FP;
    else return (x-FP/2)/FP;
};

int add_n(int x, int n){
    return x+n*FP;
};

int sub_n(int x, int n){
    return x-n*FP;
}
int mult(int x, int y){
    return ((int64_t) x)*y/FP;
};

int div(int x, int y){
    return ((int64_t) x)*FP/y;
};
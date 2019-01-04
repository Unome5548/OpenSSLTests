//
//  factorial.c
//  C_Code_TestApp
//
//  Created by Michael Patterson on 1/2/19.
//  Copyright © 2019 Microsoft. All rights reserved.
//

#include "factorial.h"

long factorial(int n){
    if (n == 0 || n == 1){
        return 1;
    }else{
        return n * factorial(n - 1);
    }
}

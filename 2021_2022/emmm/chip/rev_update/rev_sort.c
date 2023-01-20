#include "hal.h"
#include <stdint.h>
#include <stdlib.h>
#include "../simpleserial/simpleserial.h"

// DUMMY VAL

uint8_t arr[] = { 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0};

uint8_t verify(uint8_t* data, uint8_t dlen) {
  uint8_t zero = 0;
  uint8_t one = 1;
  for (int i = 0; i < 17; i++) {
    if (arr[i] != data[i]) {
      simpleserial_put('r', 1, &zero);
      return 0x00;
    }
  }
  simpleserial_put('r', 1, &one); // GOAL
  return 0x01;
}

void swap(uint8_t *xp, uint8_t *yp) {
  volatile int x, y;
  x = *xp;
  y = *yp;


  x = x * y;
  y = x / y;
  x = x / y;
  *xp = x;
  *yp = y;

}


void reverse(uint8_t* arr, int start, int end) {
  while (start < end) {
    swap(&arr[start], &arr[end]);
    start++;
    end--;
  }
}


void super_sort(uint8_t* arr, int n) {
  for (int i = 0; i < n-1; i++) {
    int min = i;
    for (int j = i; j < n; j++) {
      if (arr[j] < arr[min]) min = j;
    }
    reverse(arr, i, min);
  }
}

uint8_t sort(uint8_t* data, uint8_t dlen) {
  trigger_high();
  int n = sizeof(arr)/sizeof(arr[0]);
  super_sort(arr, n);
  simpleserial_put('r', n, arr);
  trigger_low();
  return 0;
}

int main(void) {

  platform_init();
  init_uart();
  trigger_setup();
  simpleserial_init();
  simpleserial_addcmd('a', 17, verify);
  simpleserial_addcmd('s', 0, sort);

  while(1) {
		simpleserial_get();
  }

  return 0;
}

/*
    This file is part of the ChipWhisperer Example Targets
    Copyright (C) 2012-2015 NewAE Technology Inc.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "hal.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "aes-independant.h"
#include "simpleserial.h"

uint8_t pt[32];   	// plaintext
uint8_t ct[32];   	// Ciphertext
uint8_t correct[16]="You got it!";   	// Correct
uint8_t wrong[16]="Nope!";   		// Wrong 
const uint8_t flag[]="esCTF{dummy_flag}";
int len_flag = strlen(flag);

uint8_t decrypt_and_check(uint8_t* ct, uint8_t len)
{
	trigger_high();
	static uint8_t input[16];
	static uint8_t output[16];
	
	for(int i=0;i<16;i++){
		output[i] = flag[i];
	}

	// Find input
	static uint8_t iv[16];
	for(int i=0;i<16;i++)
		iv[i] = ct[i];
		
	// Ct0
	for(int i=0;i<16;i++)
		input[i] = ct[i+16];
		
	// Decrypt in place
	for(int i = 0; i < 16; i++)
		output[i] = input[i];
	aes_indep_dec(output);

	// compute p0
	for(int i=0;i<16;i++)
		pt[i] = output[i]^iv[i];
	
	// store	
	for(int i=0;i<16;i++)
		iv[i] = input[i];
		
	// Ct1
	for(int i=0;i<16;i++)
		input[i] = ct[i+32];
		
	// Decrypt in place
	for(int i = 0; i < 16; i++)
		output[i] = input[i];
	aes_indep_dec(output);

	// compute p1
	for(int i=0;i<16;i++)
		pt[i+16] = output[i]^iv[i];
		
	// padding check
	static int is_valid=1;
	uint8_t v = pt[31];
	if (v > 16 || v==0){
		is_valid=0;
		
	}
	else{
		for(int i=15;i>=(16-v);i--){
			if (pt[i+16]!=v){
				is_valid = 0;
				break;
			}
		}
	}
	// check for flag
	for(int i=0;i<len_flag;i++){
		char one = pt[i];
		char another_one = flag[i];
		if(one != another_one){
			is_valid = 0;
			break;
		}
	}
		
	// Use output to calculate new ciphertext
	trigger_low();
	if(is_valid)
		simpleserial_put('r', 16, correct);
	else
		simpleserial_put('r', 16, wrong);
	return 0;
}


//Default key
uint8_t tmp[KEY_LENGTH] = {DEFAULT_KEY};

int main(void)
{
    	platform_init();
	init_uart();
	trigger_setup();

 	/* Uncomment this to get a HELLO message for debug */
	/*
	putch('h');
	putch('e');
	putch('l');
	putch('l');
	putch('o');
	putch('\n');
	*/

	//Initial key
	aes_indep_init();
	aes_indep_key(tmp);
    	simpleserial_addcmd('p', 48, decrypt_and_check);
    	
    	while(1)
        	simpleserial_get();
}

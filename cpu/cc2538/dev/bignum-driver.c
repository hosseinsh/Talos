/*
 * Original file:
 * Copyright (C) 2013 Texas Instruments Incorporated - http://www.ti.com/
 * All rights reserved.
 *
 * Port to Contiki:
 * Authors: Andreas Dröscher <contiki@anticat.ch>
 *          Hu Luo (sub, expmod, div)
 *          Hossein Shafagh <shafagh@inf.ethz.ch>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */
/**
 * \addtogroup cc2538-bignum
 * @{
 *
 * \file
 * Implementation of the cc2538 BigNum driver
 *
 * PKABigNumSubtractStart PKABigNumSubtractGetResult (subtraction)
 * PKABigNumAddStart      PKABigNumAddGetResult      (addition)
 * PKABigNumModStart      PKABigNumModGetStart       (modulo)
 * PKABigNumExpModStart   PKABigNumExpModGetResult   (modular exponentiation operation)
 * PKABigNumInvModStart   PKABigNumInvModGetResult   (inverse modulo operation)
 * PKABigNumMultiplyStart PKABigNumMultiplyGetStart  (multiplication)
 * PKABigNumDivideStart   PKABigNumDivideGetResult   (division)
 * PKABigNumCmpStart      PKABigNumCmpGetResult      (comparison)
 */
#include "bignum-driver.h"

#include "stdio.h"

#include "reg.h"
#include "nvic.h"

#define ASSERT(IF) if(!(IF)) return PKA_STATUS_INVALID_PARAM;

#define DEBUG 0
#if DEBUG
 #define PRINTF(...) printf(__VA_ARGS__)
#else
 #define PRINTF(...)
#endif /* DEBUG */

/*---------------------------------------------------------------------------*/
void printNumber(const uint32_t *x, int numberLength) {
  int n; for(n = numberLength - 1; n >= 0; n--){
    printf("%08x", (unsigned int)x[n]);
  }
  printf("\n");
}

/*---------------------------------------------------------------------------*/
uint8_t PKABigNumModStart(uint32_t* pui32BNum, uint8_t ui8BNSize,
                          uint32_t* pui32Modulus, uint8_t ui8ModSize,
                          uint32_t* pui32ResultVector, struct process *process) {

  uint8_t extraBuf;
  uint32_t offset;
  int i;

  // Check the arguments.
  ASSERT(NULL != pui32BNum);
  ASSERT(NULL != pui32Modulus);
  ASSERT(NULL != pui32ResultVector);

  // make sure no operation is in progress.
  if((REG(PKA_FUNCTION) & PKA_FUNCTION_RUN) != 0) {
    return (PKA_STATUS_OPERATION_INPRG);
  }

  // calculate the extra buffer requirement.
  extraBuf = 2 + ui8ModSize % 2;

  offset = 0;

  // Update the A ptr with the offset address of the PKA RAM location
  // where the number will be stored.
  REG((PKA_APTR)) = offset >> 2;

  // Load the number in PKA RAM
  for(i = 0; i < ui8BNSize; i++) {
    REG((PKA_RAM_BASE + offset + 4 * i)) = pui32BNum[i];
  }

  // determine the offset for the next data input.
  offset += 4 * (i + ui8BNSize % 2);

  // Update the B ptr with the offset address of the PKA RAM location
  // where the divisor will be stored.
  REG((PKA_BPTR)) = offset >> 2;

  // Load the divisor in PKA RAM.
  for(i = 0; i < ui8ModSize; i++) {
    REG((PKA_RAM_BASE + offset + 4 * i)) = pui32Modulus[i];
  }

  // determine the offset for the next data.
  offset += 4 * (i + extraBuf);

  // Copy the result vector address location.
  *pui32ResultVector = PKA_RAM_BASE + offset;

  // Load C ptr with the result location in PKA RAM
  REG((PKA_CPTR)) = offset >> 2;

  // Load A length registers with Big number length in 32 bit words.
  REG((PKA_ALENGTH)) = ui8BNSize;

  // Load B length registers  Divisor length in 32-bit words.
  REG((PKA_BLENGTH)) = ui8ModSize;

  // Start the PKCP modulo operation by setting the PKA Function register.
  REG((PKA_FUNCTION)) = (PKA_FUNCTION_RUN | PKA_FUNCTION_MODULO);

  // Enable Interrupt
  if(process != NULL) {
    pka_register_process_notification(process);
    nvic_interrupt_unpend(NVIC_INT_PKA);
    nvic_interrupt_enable(NVIC_INT_PKA);
  }

  return (PKA_STATUS_SUCCESS);
}
/*---------------------------------------------------------------------------*/
uint8_t PKABigNumModGetResult(uint32_t* pui32ResultBuf, uint8_t ui8Size,
                              uint32_t ui32ResVectorLoc) {

  uint32_t regMSWVal;
  uint32_t len;
  int i;

  // Check the arguments.
  ASSERT(NULL != pui32ResultBuf);
  ASSERT(ui32ResVectorLoc > PKA_RAM_BASE);
  ASSERT(ui32ResVectorLoc < (PKA_RAM_BASE + PKA_RAM_SIZE));

  // verify that the operation is complete.
  if((REG(PKA_FUNCTION) & PKA_FUNCTION_RUN) != 0) {
    return (PKA_STATUS_OPERATION_INPRG);
  }

  // Disable Interrupt
  nvic_interrupt_disable(NVIC_INT_PKA);
  pka_register_process_notification(NULL);

  //  Get the MSW register value.
  regMSWVal = REG(PKA_DIVMSW);

  // Check to make sure that the result vector is not all zeroes.
  if(regMSWVal & PKA_DIVMSW_RESULT_IS_ZERO) {
    return (PKA_STATUS_RESULT_0);
  }

  // Get the length of the result.
  len = ((regMSWVal & PKA_DIVMSW_MSW_ADDRESS_M) + 1)
      - ((ui32ResVectorLoc - PKA_RAM_BASE) >> 2);

  // If the size of the buffer provided is less than the result length than
  // return error.
  PRINTF("length= %lu\n", len);
  if(ui8Size < len) {
    return (PKA_STATUS_BUF_UNDERFLOW);
  }
  // copy the result from vector C into the pResult.
  for(i = 0; i < len; i++) {
    pui32ResultBuf[i] = REG((ui32ResVectorLoc + 4 * i));
  }

  return (PKA_STATUS_SUCCESS);
}
/*---------------------------------------------------------------------------*/
uint8_t PKABigNumCmpStart(uint32_t* pui32BNum1, uint32_t* pui32BNum2,
                          uint8_t ui8Size, struct process *process) {

  uint32_t offset;
  int i;

  // Check the arguments.
  ASSERT(NULL != pui32BNum1);
  ASSERT(NULL != pui32BNum2);

  offset = 0;

  // Make sure no operation is in progress.
  if((REG(PKA_FUNCTION) & PKA_FUNCTION_RUN) != 0) {
    return (PKA_STATUS_OPERATION_INPRG);
  }

  // Update the A ptr with the offset address of the PKA RAM location
  // where the first big number will be stored.
  REG((PKA_APTR)) = offset >> 2;

  // Load the first big number in PKA RAM.
  for(i = 0; i < ui8Size; i++) {
    REG((PKA_RAM_BASE + offset + 4 * i)) = pui32BNum1[i];
  }

  // Determine the offset in PKA RAM for the next pointer.
  offset += 4 * (i + ui8Size % 2);

  // Update the B ptr with the offset address of the PKA RAM location
  // where the second big number will be stored.
  REG((PKA_BPTR)) = offset >> 2;

  // Load the second big number in PKA RAM.
  for(i = 0; i < ui8Size; i++) {
    REG((PKA_RAM_BASE + offset + 4 * i)) = pui32BNum2[i];
  }

  // Load length registers in 32 bit word size.
  REG((PKA_ALENGTH)) = ui8Size;

  // Set the PKA Function register for the compare operation
  // and start the operation.
  REG((PKA_FUNCTION)) = (PKA_FUNCTION_RUN | PKA_FUNCTION_COMPARE);

  // Enable Interrupt
  if(process != NULL) {
    pka_register_process_notification(process);
    nvic_interrupt_unpend(NVIC_INT_PKA);
    nvic_interrupt_enable(NVIC_INT_PKA);
  }

  return (PKA_STATUS_SUCCESS);
}
/*---------------------------------------------------------------------------*/
uint8_t PKABigNumCmpGetResult(void) {
  uint8_t status;

  // verify that the operation is complete.
  if((REG(PKA_FUNCTION) & PKA_FUNCTION_RUN) != 0) {
    status = PKA_STATUS_OPERATION_INPRG;
    return (status);
  }

  // Disable Interrupt
  nvic_interrupt_disable(NVIC_INT_PKA);
  pka_register_process_notification(NULL);

  // Check the compare register.
  switch (REG(PKA_COMPARE)) {
    case PKA_COMPARE_A_EQUALS_B:
      status = PKA_STATUS_SUCCESS;
      break;

    case PKA_COMPARE_A_GREATER_THAN_B:
      status = PKA_STATUS_A_GR_B;
      break;

    case PKA_COMPARE_A_LESS_THAN_B:
      status = PKA_STATUS_A_LT_B;
      break;

    default:
      status = PKA_STATUS_FAILURE;
      break;
  }

  return (status);
}
/*---------------------------------------------------------------------------*/
uint8_t PKABigNumInvModStart(uint32_t* pui32BNum, uint8_t ui8BNSize,
                             uint32_t* pui32Modulus, uint8_t ui8Size,
                             uint32_t* pui32ResultVector, struct process *process) {

  uint32_t offset;
  int i;

  // Check the arguments.
  ASSERT(NULL != pui32BNum);
  ASSERT(NULL != pui32Modulus);
  ASSERT(NULL != pui32ResultVector);

  offset = 0;

  // Make sure no operation is in progress.
  if((REG(PKA_FUNCTION) & PKA_FUNCTION_RUN) != 0) {
    return (PKA_STATUS_OPERATION_INPRG);
  }

  // Update the A ptr with the offset address of the PKA RAM location
  // where the number will be stored.
  REG((PKA_APTR)) = offset >> 2;

  // Load the \e pui32BNum number in PKA RAM.
  for(i = 0; i < ui8BNSize; i++) {
    REG((PKA_RAM_BASE + offset + 4 * i)) = pui32BNum[i];
  }

  // Determine the offset for next data.
  offset += 4 * (i + ui8BNSize % 2);

  // Update the B ptr with the offset address of the PKA RAM location
  // where the modulus will be stored.
  REG((PKA_BPTR)) = offset >> 2;

  // Load the \e pui32Modulus divisor in PKA RAM.
  for(i = 0; i < ui8Size; i++) {
    REG((PKA_RAM_BASE + offset + 4 * i)) = pui32Modulus[i];
  }

  // Determine the offset for result data.
  offset += 4 * (i + ui8Size % 2);

  // Copy the result vector address location.
  *pui32ResultVector = PKA_RAM_BASE + offset;

  // Load D ptr with the result location in PKA RAM.
  REG((PKA_DPTR)) = offset >> 2;

  // Load the respective length registers.
  REG((PKA_ALENGTH)) = ui8BNSize;
  REG((PKA_BLENGTH)) = ui8Size;

  // set the PKA function to InvMod operation and the start the operation.
  REG((PKA_FUNCTION)) = 0x0000F000;

  // Enable Interrupt
  if(process != NULL) {
    pka_register_process_notification(process);
    nvic_interrupt_unpend(NVIC_INT_PKA);
    nvic_interrupt_enable(NVIC_INT_PKA);
  }

  return (PKA_STATUS_SUCCESS);
}
/*---------------------------------------------------------------------------*/
uint8_t PKABigNumInvModGetResult(uint32_t* pui32ResultBuf, uint8_t ui8Size,
                                 uint32_t ui32ResVectorLoc) {

  uint32_t regMSWVal;
  uint32_t len;
  int i;

  // Check the arguments.
  ASSERT(NULL != pui32ResultBuf);
  ASSERT(ui32ResVectorLoc > PKA_RAM_BASE);
  ASSERT(ui32ResVectorLoc < (PKA_RAM_BASE + PKA_RAM_SIZE));

  // Verify that the operation is complete.
  if((REG(PKA_FUNCTION) & PKA_FUNCTION_RUN) != 0) {
    return (PKA_STATUS_OPERATION_INPRG);
  }

  // Disable Interrupt
  nvic_interrupt_disable(NVIC_INT_PKA);
  pka_register_process_notification(NULL);

  // Get the MSW register value.
  regMSWVal = REG(PKA_MSW);

  // Check to make sure that the result vector is not all zeroes.
  if(regMSWVal & PKA_MSW_RESULT_IS_ZERO) {
    return (PKA_STATUS_RESULT_0);
  }

  // Get the length of the result
  len = ((regMSWVal & PKA_MSW_MSW_ADDRESS_M) + 1)
      - ((ui32ResVectorLoc - PKA_RAM_BASE) >> 2);

  // Check if the provided buffer length is adequate to store the result
  // data.
  PRINTF("length= %lu\n", len);
  if(ui8Size < len) {
    return (PKA_STATUS_BUF_UNDERFLOW);
  }

  // Copy the result from vector C into the \e pui32ResultBuf.
  for(i = 0; i < len; i++) {
    pui32ResultBuf[i] = REG((ui32ResVectorLoc + 4 * i));
  }

  return (PKA_STATUS_SUCCESS);
}
/*---------------------------------------------------------------------------*/
uint8_t PKABigNumMultiplyStart(uint32_t* pui32Xplicand, uint8_t ui8XplicandSize,
                               uint32_t* pui32Xplier, uint8_t ui8XplierSize,
                               uint32_t* pui32ResultVector, struct process *process) {

  uint32_t offset;
  int i;

  // Check for the arguments.
  ASSERT(NULL != pui32Xplicand);
  ASSERT(NULL != pui32Xplier);
  ASSERT(NULL != pui32ResultVector);

  offset = 0;

  // Make sure no operation is in progress.
  if((REG(PKA_FUNCTION) & PKA_FUNCTION_RUN) != 0) {
    return (PKA_STATUS_OPERATION_INPRG);
  }

  // Update the A ptr with the offset address of the PKA RAM location
  // where the multiplicand will be stored.
  REG((PKA_APTR)) = offset >> 2;

  // Load the multiplicand in PKA RAM.
  for(i = 0; i < ui8XplicandSize; i++) {
    REG((PKA_RAM_BASE + offset + 4 * i)) = *pui32Xplicand;
    pui32Xplicand++;
  }

  // Determine the offset for the next data.
  offset += 4 * (i + (ui8XplicandSize % 2));

  // Update the B ptr with the offset address of the PKA RAM location
  // where the multiplier will be stored.
  REG((PKA_BPTR)) = offset >> 2;

  // Load the multiplier in PKA RAM.
  for(i = 0; i < ui8XplierSize; i++) {
    REG((PKA_RAM_BASE + offset + 4 * i)) = *pui32Xplier;
    pui32Xplier++;
  }

  // Determine the offset for the next data.
  offset += 4 * (i + (ui8XplierSize % 2));

  // Copy the result vector address location.
  *pui32ResultVector = PKA_RAM_BASE + offset;

  // Load C ptr with the result location in PKA RAM.
  REG((PKA_CPTR)) = offset >> 2;

  // Load the respective length registers.
  REG((PKA_ALENGTH)) = ui8XplicandSize;
  REG((PKA_BLENGTH)) = ui8XplierSize;

  // Set the PKA function to the multiplication and start it.
  REG((PKA_FUNCTION)) = (PKA_FUNCTION_RUN | PKA_FUNCTION_MULTIPLY);

  // Enable Interrupt
  if(process != NULL) {
    pka_register_process_notification(process);
    nvic_interrupt_unpend(NVIC_INT_PKA);
    nvic_interrupt_enable(NVIC_INT_PKA);
  }

  return (PKA_STATUS_SUCCESS);
}
/*---------------------------------------------------------------------------*/
uint8_t PKABigNumMultGetResult(uint32_t* pui32ResultBuf, uint32_t* pui32Len,
                               uint32_t ui32ResVectorLoc) {

  uint32_t regMSWVal;
  uint32_t len;
  int i;

  // Check for arguments.
  ASSERT(NULL != pui32ResultBuf);
  ASSERT(NULL != pui32Len);
  ASSERT(ui32ResVectorLoc > PKA_RAM_BASE);
  ASSERT(ui32ResVectorLoc < (PKA_RAM_BASE + PKA_RAM_SIZE));

  // Verify that the operation is complete.
  if((REG(PKA_FUNCTION) & PKA_FUNCTION_RUN) != 0) {
    return (PKA_STATUS_OPERATION_INPRG);
  }

  // Disable Interrupt
  nvic_interrupt_disable(NVIC_INT_PKA);
  pka_register_process_notification(NULL);

  // Get the MSW register value.
  regMSWVal = REG(PKA_MSW);

  // Check to make sure that the result vector is not all zeroes.
  if(regMSWVal & PKA_MSW_RESULT_IS_ZERO) {
    return (PKA_STATUS_RESULT_0);
  }

  // Get the length of the result.
  len = ((regMSWVal & PKA_MSW_MSW_ADDRESS_M) + 1)
      - ((ui32ResVectorLoc - PKA_RAM_BASE) >> 2);

  // Make sure that the length of the supplied result buffer is adequate
  // to store the resultant.
  PRINTF("length= %lu\n", len);
  if(*pui32Len < len) {
    return (PKA_STATUS_BUF_UNDERFLOW);
  }

  // Copy the resultant length.
  *pui32Len = len;

  // Copy the result from vector C into the pResult.
  for(i = 0; i < *pui32Len; i++) {
    pui32ResultBuf[i] = REG((ui32ResVectorLoc + 4 * i));
  }

  return (PKA_STATUS_SUCCESS);
}
/*---------------------------------------------------------------------------*/
uint8_t PKABigNumAddStart(uint32_t* pui32BN1, uint8_t ui8BN1Size,
                          uint32_t* pui32BN2, uint8_t ui8BN2Size,
                          uint32_t* pui32ResultVector, struct process *process) {

  uint32_t offset;
  int i;

  // Check for arguments.
  ASSERT(NULL != pui32BN1);
  ASSERT(NULL != pui32BN2);
  ASSERT(NULL != pui32ResultVector);

  offset = 0;

  // Make sure no operation is in progress.
  if((REG(PKA_FUNCTION) & PKA_FUNCTION_RUN) != 0) {
    return (PKA_STATUS_OPERATION_INPRG);
  }

  // Update the A ptr with the offset address of the PKA RAM location
  // where the big number 1 will be stored.
  REG((PKA_APTR)) = offset >> 2;

  // Load the big number 1 in PKA RAM.
  for(i = 0; i < ui8BN1Size; i++) {
    REG((PKA_RAM_BASE + offset + 4 * i)) = pui32BN1[i];
  }

  // Determine the offset in PKA RAM for the next data.
  offset += 4 * (i + (ui8BN1Size % 2));

  // Update the B ptr with the offset address of the PKA RAM location
  // where the big number 2 will be stored.
  REG((PKA_BPTR)) = offset >> 2;

  // Load the big number 2 in PKA RAM.
  for(i = 0; i < ui8BN2Size; i++) {
    REG((PKA_RAM_BASE + offset + 4 * i)) = pui32BN2[i];
  }

  // Determine the offset in PKA RAM for the next data.
  offset += 4 * (i + (ui8BN2Size % 2));

  // Copy the result vector address location.
  *pui32ResultVector = PKA_RAM_BASE + offset;

  // Load C ptr with the result location in PKA RAM.
  REG((PKA_CPTR)) = offset >> 2;

  // Load respective length registers.
  REG((PKA_ALENGTH)) = ui8BN1Size;
  REG((PKA_BLENGTH)) = ui8BN2Size;

  // Set the function for the add operation and start the operation.
  REG((PKA_FUNCTION)) = (PKA_FUNCTION_RUN | PKA_FUNCTION_ADD);

  // Enable Interrupt
  if(process != NULL) {
    pka_register_process_notification(process);
    nvic_interrupt_unpend(NVIC_INT_PKA);
    nvic_interrupt_enable(NVIC_INT_PKA);
  }

  return (PKA_STATUS_SUCCESS);
}
/*---------------------------------------------------------------------------*/
uint8_t PKABigNumAddGetResult(uint32_t* pui32ResultBuf, uint32_t* pui32Len,
                              uint32_t ui32ResVectorLoc) {

  uint32_t regMSWVal;
  uint32_t len;
  int i;

  // Check for the arguments.
  ASSERT(NULL != pui32ResultBuf);
  ASSERT(NULL != pui32Len);
  ASSERT(ui32ResVectorLoc > PKA_RAM_BASE);
  ASSERT(ui32ResVectorLoc < (PKA_RAM_BASE + PKA_RAM_SIZE));

  // Verify that the operation is complete.
  if((REG(PKA_FUNCTION) & PKA_FUNCTION_RUN) != 0) {
    return (PKA_STATUS_OPERATION_INPRG);
  }

  // Disable Interrupt
  nvic_interrupt_disable(NVIC_INT_PKA);
  pka_register_process_notification(NULL);

  // Get the MSW register value.
  regMSWVal = REG(PKA_MSW);

  // Check to make sure that the result vector is not all zeroes.
  if(regMSWVal & PKA_MSW_RESULT_IS_ZERO) {
    return (PKA_STATUS_RESULT_0);
  }

  // Get the length of the result.
  len = ((regMSWVal & PKA_MSW_MSW_ADDRESS_M) + 1)
      - ((ui32ResVectorLoc - PKA_RAM_BASE) >> 2);

  // Make sure that the supplied result buffer is adequate to store the
  // resultant data.
  PRINTF("length= %lu\n", len);
  if(*pui32Len < len) {
    return (PKA_STATUS_BUF_UNDERFLOW);
  }

  // Copy the length.
  *pui32Len = len;

  // Copy the result from vector C into the provided buffer.
  for(i = 0; i < *pui32Len; i++) {
    pui32ResultBuf[i] = REG((ui32ResVectorLoc + 4 * i));
  }

  return (PKA_STATUS_SUCCESS);
}
//--------------------------------------------------------------------
// below functions are added by hu luo
uint8_t PKABigNumSubtractStart(uint32_t* pui32BN1, uint8_t ui8BN1Size,
                               uint32_t* pui32BN2, uint8_t ui8BN2Size,
                               uint32_t* pui32ResultVector, struct process *process) {

  uint32_t offset;
  int i;

  // Check for arguments.
  ASSERT(NULL != pui32BN1);
  ASSERT(NULL != pui32BN2);
  ASSERT(NULL != pui32ResultVector);

  offset = 0;

  // Make sure no operation is in progress.
  if((REG(PKA_FUNCTION) & PKA_FUNCTION_RUN) != 0) {
    return (PKA_STATUS_OPERATION_INPRG);
  }

  // Update the A ptr with the offset address of the PKA RAM location
  // where the big number 1 will be stored.
  REG((PKA_APTR)) = offset >> 2;

  // Load the big number 1 in PKA RAM.
  for(i = 0; i < ui8BN1Size; i++) {
    REG((PKA_RAM_BASE + offset + 4 * i)) = pui32BN1[i];
  }

  // Determine the offset in PKA RAM for the next data.
  offset += 4 * (i + (ui8BN1Size % 2));

  // Update the B ptr with the offset address of the PKA RAM location
  // where the big number 2 will be stored.
  REG((PKA_BPTR)) = offset >> 2;

  // Load the big number 2 in PKA RAM.
  for(i = 0; i < ui8BN2Size; i++) {
    REG((PKA_RAM_BASE + offset + 4 * i)) = pui32BN2[i];
  }

  // Determine the offset in PKA RAM for the next data.
  offset += 4 * (i + (ui8BN2Size % 2));

  // Copy the result vector address location.
  *pui32ResultVector = PKA_RAM_BASE + offset;

  // Load C ptr with the result location in PKA RAM.
  REG((PKA_CPTR)) = offset >> 2;

  // Load respective length registers.
  REG((PKA_ALENGTH)) = ui8BN1Size;
  REG((PKA_BLENGTH)) = ui8BN2Size;

  // Set the function for the add operation and start the operation.
  REG((PKA_FUNCTION)) = (PKA_FUNCTION_RUN | PKA_FUNCTION_SUBTRACT);

  // Enable Interrupt
  if(process != NULL) {
    pka_register_process_notification(process);
    nvic_interrupt_unpend(NVIC_INT_PKA);
    nvic_interrupt_enable(NVIC_INT_PKA);
  }

  return (PKA_STATUS_SUCCESS);
}
/*---------------------------------------------------------------------------*/
uint8_t PKABigNumSubtractGetResult(uint32_t* pui32ResultBuf, uint32_t* pui32Len,
                                   uint32_t ui32ResVectorLoc) {

  uint32_t regMSWVal;
  uint32_t len;
  int i;

  // Check for the arguments.
  ASSERT(NULL != pui32ResultBuf);
  ASSERT(NULL != pui32Len);
  ASSERT(ui32ResVectorLoc > PKA_RAM_BASE);
  ASSERT(ui32ResVectorLoc < (PKA_RAM_BASE + PKA_RAM_SIZE));

  // Verify that the operation is complete.
  if((REG(PKA_FUNCTION) & PKA_FUNCTION_RUN) != 0) {
    return (PKA_STATUS_OPERATION_INPRG);
  }

  // Disable Interrupt
  nvic_interrupt_disable(NVIC_INT_PKA);
  pka_register_process_notification(NULL);

  // Get the MSW register value.
  regMSWVal = REG(PKA_MSW);

  // Check to make sure that the result vector is not all zeroes.
  if(regMSWVal & PKA_MSW_RESULT_IS_ZERO) {
    return (PKA_STATUS_RESULT_0);
  }

  // Get the length of the result.
  len = ((regMSWVal & PKA_MSW_MSW_ADDRESS_M) + 1)
      - ((ui32ResVectorLoc - PKA_RAM_BASE) >> 2);

  // Make sure that the supplied result buffer is adequate to store the
  // resultant data.
  PRINTF("length= %lu\n", len);
  if(*pui32Len < len) {
    return (PKA_STATUS_BUF_UNDERFLOW);
  }

  // Copy the length.
  *pui32Len = len;

  // Copy the result from vector C into the provided buffer.
  for(i = 0; i < *pui32Len; i++) {
    pui32ResultBuf[i] = REG((ui32ResVectorLoc + 4 * i));
  }

  return (PKA_STATUS_SUCCESS);
}
/*---------------------------------------------------------------------------*/
extern uint8_t PKABigNumExpModStart(uint32_t* pui32BNum, uint8_t ui8BNSize,
                                    uint32_t* pui32Modulus, uint8_t ui8ModSize,
                                    uint32_t* pui32Base, uint8_t ui8BaseSize,
                                    uint32_t* pui32ResultVector,
                                    struct process *process) {
  uint32_t offset;
  int i;

  // Check for the arguments.
  ASSERT(NULL != pui32BNum);
  //ASSERT(NULL != ui8BNSize);
  ASSERT(NULL != pui32Modulus);
  //ASSERT(NULL != ui8ModSize);
  ASSERT(NULL != pui32Base);
  //ASSERT(NULL != ui8BaseSize);
  ASSERT(NULL != pui32ResultVector);
  ASSERT(pui32Modulus != pui32Base);

  offset = 0;

  // Make sure no PKA operation is in progress.
  if((REG(PKA_FUNCTION) & PKA_FUNCTION_RUN) != 0) {
    return (PKA_STATUS_OPERATION_INPRG);
  }

  // Update the A ptr with the offset address of the PKA RAM location
  // where the exponent will be stored.
  REG((PKA_APTR)) = offset >> 2;

  // Load the Exponent in PKA RAM.
  for(i = 0; i < ui8BNSize; i++) {
    REG((PKA_RAM_BASE + offset + 4 * i)) = pui32BNum[i];
    //PRINTF("the A register is ,%d\n",pui32BNum[i]);
  }

  // Determine the offset for the next data(BPTR).
  offset += 4 * (i + ui8BNSize % 2);
  PRINTF("the B offset is ,%d\n",offset);
  // Update the B ptr with the offset address of the PKA RAM location
  // where the divisor will be stored.
  REG((PKA_BPTR)) = offset >> 2;

  // Load the Modulus in PKA RAM.
  for(i = 0; i < ui8ModSize; i++) {
    REG((PKA_RAM_BASE + offset + 4 * i)) = pui32Modulus[i];
    //PRINTF("the B register is ,%X\n",pui32Modulus[i]);
  }

  // Determine the offset for the next data(CPTR).
  offset += 4 * (i + ui8ModSize % 2 + 2);
  PRINTF("the C offset is ,%d\n",offset);
  // Update the C ptr with the offset address of the PKA RAM location
  // where the Base will be stored.
  REG((PKA_CPTR)) = offset >> 2;

  // Write Base to the Vector C in PKA RAM

  for(i = 0; i < ui8BaseSize; i++) {
    REG((PKA_RAM_BASE + offset + 4 * i)) = pui32Base[i];
    //PRINTF("the C register is ,%X\n",pui32Base[i]);
  }

  // Determine the offset for the next data.
  /*INFO D and B can share the same memory area!*/
  //offset += 4 * (i + extraBuf + 2);

  PRINTF("the D offset is ,%d\n",offset);
  // Copy the result vector address location.
  *pui32ResultVector = PKA_RAM_BASE + offset;

  // Load D ptr with the result location in PKA RAM
  REG((PKA_DPTR)) = offset >> 2;

  // Load A length registers with Big number length in 32 bit words.
  REG((PKA_ALENGTH)) = ui8BNSize;

  // Load B length registers  Divisor length in 32-bit words.
  REG((PKA_BLENGTH)) = ui8ModSize;
  //REG((PKA_SHIFT)) = 0x00000001; Required for (EXPMod-variable): 0x0000A000
  // Start the PKCP modulo exponentiation operation(EXPMod-ACT2)by setting the PKA Function register.
  REG((PKA_FUNCTION)) = 0x0000C000;

  // Enable Interrupt
  if(process != NULL) {
    pka_register_process_notification(process);
    nvic_interrupt_unpend(NVIC_INT_PKA);
    nvic_interrupt_enable(NVIC_INT_PKA);
  }

  return (PKA_STATUS_SUCCESS);
}
//--------------------------------------------------------------------------------
uint8_t PKABigNumExpModGetResult(uint32_t* pui32ResultBuf, uint8_t ui8Size,
                                 uint32_t ui32ResVectorLoc) {

  uint32_t regMSWVal;
  uint32_t len;
  int i;

  // Check the arguments.
  ASSERT(NULL != pui32ResultBuf);
  ASSERT(ui32ResVectorLoc > PKA_RAM_BASE);
  ASSERT(ui32ResVectorLoc < (PKA_RAM_BASE + PKA_RAM_SIZE));

  // verify that the operation is complete.
  if((REG(PKA_FUNCTION) & PKA_FUNCTION_RUN) != 0) {
    return (PKA_STATUS_OPERATION_INPRG);
  }

  // Disable Interrupt
  nvic_interrupt_disable(NVIC_INT_PKA);
  pka_register_process_notification(NULL);

  //  Get the MSW register value.
  regMSWVal = REG(PKA_MSW);

    // Check to make sure that the result vector is not all zeroes.
    if(regMSWVal & PKA_MSW_RESULT_IS_ZERO) {
      return (PKA_STATUS_RESULT_0);
    }

    // Get the length of the result
    len = ((regMSWVal & PKA_MSW_MSW_ADDRESS_M) + 1)
        - ((ui32ResVectorLoc - PKA_RAM_BASE) >> 2);
  // If the size of the buffer provided is less than the result length than
  // return error.
  PRINTF("length= %lu\n", len);
  if(ui8Size < len) {
    return (PKA_STATUS_BUF_UNDERFLOW);
  }

  // copy the result from vector C into the pResult.
  for(i = 0; i < len; i++) {
    pui32ResultBuf[i] = REG((ui32ResVectorLoc + 4 * i));
  }

  return (PKA_STATUS_SUCCESS);
}

/*---------------------------------------------------------------------------*/
uint8_t PKABigNumDivideStart(uint32_t* pui32Xdividend, uint8_t ui8XdividendSize,
                             uint32_t* pui32Xdivisor, uint8_t ui8XdivisorSize,
                             uint32_t* pui32ResultVector, struct process *process) {

  uint32_t offset;
  uint32_t spacing;
  int i;

  // We use largest len for spacing
  if(ui8XdividendSize > ui8XdivisorSize) {
    spacing = ui8XdividendSize;
  } else {
    spacing = ui8XdivisorSize;
  }
  spacing += 2 + spacing % 2;

  // Check for the arguments.
  ASSERT(NULL != pui32Xdividend);
  ASSERT(NULL != pui32Xdivisor);
  ASSERT(NULL != pui32ResultVector);

  // Make sure no operation is in progress.
  if((REG(PKA_FUNCTION) & PKA_FUNCTION_RUN) != 0) {
    return (PKA_STATUS_OPERATION_INPRG);
  }

  // Update the A ptr with the offset address of the PKA RAM location
  // where the multiplicand will be stored.
  offset = 0;
  REG((PKA_APTR)) = offset >> 2;

  // Load the multiplicand in PKA RAM.
  for(i = 0; i < ui8XdividendSize; i++) {
    REG((PKA_RAM_BASE + offset + 4 * i)) = *pui32Xdividend;
    pui32Xdividend++;
  }

  // Determine the offset for the next data.
  offset += 4 * spacing;

  // Update the B ptr with the offset address of the PKA RAM location
  // where the multiplier will be stored.
  REG((PKA_BPTR)) = offset >> 2;

  // Load the multiplier in PKA RAM.
  for(i = 0; i < ui8XdivisorSize; i++) {
    REG((PKA_RAM_BASE + offset + 4 * i)) = *pui32Xdivisor;
    pui32Xdivisor++;
  }

  // Determine the offset for the reminder.
  offset += 4 * spacing;

  // Load C ptr with the result location in PKA RAM.
  REG((PKA_CPTR)) = offset >> 2;

  // Determine the offset for the quotient.
  offset += 4 * spacing;

  // Copy the quotient vector address location.
  *pui32ResultVector = PKA_RAM_BASE + offset;

  // Load D ptr with the result location in PKA RAM.
  REG((PKA_DPTR)) = offset >> 2;

  // Load the respective length registers.
  REG((PKA_ALENGTH)) = ui8XdividendSize;
  REG((PKA_BLENGTH)) = ui8XdivisorSize;

  // Set the PKA function to the multiplication and start it.
  REG((PKA_FUNCTION)) = (PKA_FUNCTION_RUN | PKA_FUNCTION_DIVIDE);

  // Enable Interrupt
  if(process != NULL) {
    pka_register_process_notification(process);
    nvic_interrupt_unpend(NVIC_INT_PKA);
    nvic_interrupt_enable(NVIC_INT_PKA);
  }

  return (PKA_STATUS_SUCCESS);
}

/*---------------------------------------------------------------------------*/
uint8_t PKABigNumDivideGetResult(uint32_t* pui32ResultBuf, uint32_t* pui32Len,
                                 uint32_t ui32ResVectorLoc) {

  uint32_t regMSWVal;
  uint32_t len;
  int i;

  // Check for arguments.
  ASSERT(NULL != pui32ResultBuf);
  ASSERT(NULL != pui32Len);
  ASSERT(ui32ResVectorLoc > PKA_RAM_BASE);
  ASSERT(ui32ResVectorLoc < (PKA_RAM_BASE + PKA_RAM_SIZE));

  // Verify that the operation is complete.
  if((REG(PKA_FUNCTION) & PKA_FUNCTION_RUN) != 0) {
    return (PKA_STATUS_OPERATION_INPRG);
  }

  // Disable Interrupt
  nvic_interrupt_disable(NVIC_INT_PKA);
  pka_register_process_notification(NULL);

  // Get the MSW register value.
  regMSWVal = REG(PKA_MSW);

  // Check to make sure that the result vector is not all zeroes.
  if(regMSWVal & PKA_MSW_RESULT_IS_ZERO) {
    return (PKA_STATUS_RESULT_0);
  }

  // Get the length of the result.
  len = ((regMSWVal & PKA_MSW_MSW_ADDRESS_M) + 1)
      - ((ui32ResVectorLoc - PKA_RAM_BASE) >> 2);

  // Make sure that the length of the supplied result buffer is adequate
  // to store the resultant.
  PRINTF("length= %lu\n", len);
  if(*pui32Len < len) {
    return (PKA_STATUS_BUF_UNDERFLOW);
  }

  // Copy the resultant length.
  *pui32Len = len;

  // Copy the result from vector C into the pResult.
  for(i = 0; i < *pui32Len; i++) {
    pui32ResultBuf[i] = REG((ui32ResVectorLoc + 4 * i));
  }

  return (PKA_STATUS_SUCCESS);
}

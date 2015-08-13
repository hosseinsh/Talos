/*
 * Original file:
 * Copyright (C) 2013 Texas Instruments Incorporated - http://www.ti.com/
 * All rights reserved.
 *
 * Port to Contiki:
 * Copyright (c) 2014 Andreas Dröscher <contiki@anticat.ch>
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
 * \addtogroup cc2538-ecc
 * @{
 *
 * \file
 * Implementation of the cc2538 ECC driver
 */
#include "ecc-driver.h"
#include "reg.h"
#include "dev/nvic.h"

#define ASSERT(IF) if(!(IF)) return PKA_STATUS_INVALID_PARAM;

/*---------------------------------------------------------------------------*/
uint8_t PKAECCMultiplyStart(uint32_t* pui32Scalar, ec_point_t* ptEcPt,
                            ecc_curve_info_t* ptCurve, uint32_t* pui32ResultVector,
                            struct process *process) {

  uint8_t extraBuf;
  uint32_t offset;
  int i;

  // Check for the arguments.
  ASSERT(NULL != pui32Scalar);
  ASSERT(NULL != ptEcPt);
  ASSERT(NULL != ptEcPt->pui32X);
  ASSERT(NULL != ptEcPt->pui32Y);
  ASSERT(NULL != ptCurve);
  ASSERT(ptCurve->ui8Size <= PKA_MAX_CURVE_SIZE);
  ASSERT(NULL != pui32ResultVector);

  offset = 0;

  // Make sure no PKA operation is in progress.
  if((REG(PKA_FUNCTION) & PKA_FUNCTION_RUN) != 0) {
    return (PKA_STATUS_OPERATION_INPRG);
  }

  // Calculate the extra buffer requirement.
  extraBuf = 2 + ptCurve->ui8Size % 2;

  // Update the A ptr with the offset address of the PKA RAM location
  // where the scalar will be stored.
  REG((PKA_APTR)) = offset >> 2;

  // Load the scalar in PKA RAM.
  for(i = 0; i < ptCurve->ui8Size; i++) {
    REG((PKA_RAM_BASE + offset + 4 * i)) = *pui32Scalar++;
  }

  // Determine the offset for the next data.
  offset += 4 * (i + (ptCurve->ui8Size % 2));

  // Update the B ptr with the offset address of the PKA RAM location
  // where the curve parameters will be stored.
  REG((PKA_BPTR)) = offset >> 2;

  // Write curve parameter 'p' as 1st part of vector B immediately
  // following vector A at PKA RAM
  for(i = 0; i < ptCurve->ui8Size; i++) {
    REG((PKA_RAM_BASE + offset + 4 * i)) = (uint32_t) ptCurve->pui32Prime[i];
  }

  // Determine the offset for the next data.
  offset += 4 * (i + extraBuf);

  // Copy curve parameter 'a' in PKA RAM.
  for(i = 0; i < ptCurve->ui8Size; i++) {
    REG((PKA_RAM_BASE + offset + 4 * i)) = (uint32_t) ptCurve->pui32A[i];
  }

  // Determine the offset for the next data.
  offset += 4 * (i + extraBuf);

  // Copy curve parameter 'b' in PKA RAM.
  for(i = 0; i < ptCurve->ui8Size; i++) {
    REG((PKA_RAM_BASE + offset + 4 * i)) = (uint32_t) ptCurve->pui32B[i];
  }

  // Determine the offset for the next data.
  offset += 4 * (i + extraBuf);

  // Update the C ptr with the offset address of the PKA RAM location
  // where the Gx, Gy will be stored.
  REG((PKA_CPTR)) = offset >> 2;

  // Write elliptic curve point x co-ordinate value.
  for(i = 0; i < ptCurve->ui8Size; i++) {
    REG((PKA_RAM_BASE + offset + 4 * i)) = ptEcPt->pui32X[i];
  }

  // Determine the offset for the next data.
  offset += 4 * (i + extraBuf);

  // Write elliptic curve point y co-ordinate value.
  for(i = 0; i < ptCurve->ui8Size; i++) {
    REG((PKA_RAM_BASE + offset + 4 * i)) = ptEcPt->pui32Y[i];
  }

  // Determine the offset for the next data.
  offset += 4 * (i + extraBuf);

  // Update the result location.
  *pui32ResultVector = PKA_RAM_BASE + offset;

  // Load D ptr with the result location in PKA RAM.
  REG(PKA_DPTR) = offset >> 2;

  // Load length registers.
  REG(PKA_ALENGTH) = ptCurve->ui8Size;
  REG(PKA_BLENGTH) = ptCurve->ui8Size;

  // set the PKA function to ECC-MULT and start the operation.
  REG(PKA_FUNCTION) = 0x0000D000;

  // Enable Interrupt
  if(process != NULL) {
    pka_register_process_notification(process);
    nvic_interrupt_unpend(NVIC_INT_PKA);
    nvic_interrupt_enable(NVIC_INT_PKA);
  }

  return (PKA_STATUS_SUCCESS);
}
/*---------------------------------------------------------------------------*/
uint8_t PKAECCMultiplyGetResult(ec_point_t* ptOutEcPt,
                                uint32_t ui32ResVectorLoc) {
  int i;
  uint32_t addr;
  uint32_t regMSWVal;
  uint32_t len;

  // Check for the arguments.
  ASSERT(NULL != ptOutEcPt);
  ASSERT(NULL != ptOutEcPt->pui32X);
  ASSERT(NULL != ptOutEcPt->pui32Y);
  ASSERT(ui32ResVectorLoc > PKA_RAM_BASE);
  ASSERT(ui32ResVectorLoc < (PKA_RAM_BASE + PKA_RAM_SIZE));

  // Verify that the operation is completed.
  if((REG(PKA_FUNCTION) & PKA_FUNCTION_RUN) != 0) {
    return (PKA_STATUS_OPERATION_INPRG);
  }

  // Disable Interrupt
  nvic_interrupt_disable(NVIC_INT_PKA);
  pka_register_process_notification(NULL);

  if(REG(PKA_SHIFT) == 0x00000000) {
    // Get the MSW register value.
    regMSWVal = REG(PKA_MSW);

    // Check to make sure that the result vector is not all zeroes.
    if(regMSWVal & PKA_MSW_RESULT_IS_ZERO) {
      return (PKA_STATUS_RESULT_0);
    }

    // Get the length of the result
    len = ((regMSWVal & PKA_MSW_MSW_ADDRESS_M) + 1)
        - ((ui32ResVectorLoc - PKA_RAM_BASE) >> 2);

    addr = ui32ResVectorLoc;

    // copy the x co-ordinate value of the result from vector D into
    // the \e ptOutEcPt.
    for(i = 0; i < len; i++) {
      ptOutEcPt->pui32X[i] = REG(addr + 4 * i);
    }

    addr += 4 * (i + 2 + len % 2);

    // copy the y co-ordinate value of the result from vector D into
    // the \e ptOutEcPt.
    for(i = 0; i < len; i++) {
      ptOutEcPt->pui32Y[i] = REG(addr + 4 * i);
    }

    return (PKA_STATUS_SUCCESS);
  } else {
    return (PKA_STATUS_FAILURE);
  }
}
/*---------------------------------------------------------------------------*/
uint8_t PKAECCMultGenPtStart(uint32_t* pui32Scalar, ecc_curve_info_t* ptCurve,
                             uint32_t* pui32ResultVector, struct process *process) {
  uint8_t extraBuf;
  uint32_t offset;
  int i;

  // check for the arguments.
  ASSERT(NULL != pui32Scalar);
  ASSERT(NULL != ptCurve);
  ASSERT(ptCurve->ui8Size <= PKA_MAX_CURVE_SIZE);
  ASSERT(NULL != pui32ResultVector);

  offset = 0;

  // Make sure no operation is in progress.
  if((REG(PKA_FUNCTION) & PKA_FUNCTION_RUN) != 0) {
    return (PKA_STATUS_OPERATION_INPRG);
  }

  // Calculate the extra buffer requirement.
  extraBuf = 2 + ptCurve->ui8Size % 2;

  // Update the A ptr with the offset address of the PKA RAM location
  // where the scalar will be stored.
  REG(PKA_APTR) = offset >> 2;

  // Load the scalar in PKA RAM.
  for(i = 0; i < ptCurve->ui8Size; i++) {
    REG((PKA_RAM_BASE + offset + 4 * i)) = *pui32Scalar++;
  }

  // Determine the offset in PKA RAM for the next data.
  offset += 4 * (i + (ptCurve->ui8Size % 2));

  // Update the B ptr with the offset address of the PKA RAM location
  // where the curve parameters will be stored.
  REG(PKA_BPTR) = offset >> 2;

  // Write curve parameter 'p' as 1st part of vector B.
  for(i = 0; i < ptCurve->ui8Size; i++) {
    REG((PKA_RAM_BASE + offset + 4 * i)) = (uint32_t) ptCurve->pui32Prime[i];
  }

  // Determine the offset in PKA RAM for the next data.
  offset += 4 * (i + extraBuf);

  // Write curve parameter 'a' in PKA RAM.
  for(i = 0; i < ptCurve->ui8Size; i++) {
    REG((PKA_RAM_BASE + offset + 4 * i)) = (uint32_t) ptCurve->pui32A[i];
  }

  // Determine the offset in PKA RAM for the next data.
  offset += 4 * (i + extraBuf);

  // write curve parameter 'b' in PKA RAM.
  for(i = 0; i < ptCurve->ui8Size; i++) {
    REG((PKA_RAM_BASE + offset + 4 * i)) = (uint32_t) ptCurve->pui32B[i];
  }

  // Determine the offset in PKA RAM for the next data.
  offset += 4 * (i + extraBuf);

  // Update the C ptr with the offset address of the PKA RAM location
  // where the Gx, Gy will be stored.
  REG(PKA_CPTR) = offset >> 2;

  // Write x co-ordinate value of the Generator point in PKA RAM.
  for(i = 0; i < ptCurve->ui8Size; i++) {
    REG((PKA_RAM_BASE + offset + 4 * i)) = (uint32_t) ptCurve->pui32Gx[i];
  }

  // Determine the offset in PKA RAM for the next data.
  offset += 4 * (i + extraBuf);

  // Write y co-ordinate value of the Generator point in PKA RAM.
  for(i = 0; i < ptCurve->ui8Size; i++) {
    REG((PKA_RAM_BASE + offset + 4 * i)) = (uint32_t) ptCurve->pui32Gy[i];
  }

  // Determine the offset in PKA RAM for the next data.
  offset += 4 * (i + extraBuf);

  // Update the result location.
  *pui32ResultVector = PKA_RAM_BASE + offset;

  // Load D ptr with the result location in PKA RAM.
  REG(PKA_DPTR) = offset >> 2;

  // Load length registers.
  REG(PKA_ALENGTH) = ptCurve->ui8Size;
  REG(PKA_BLENGTH) = ptCurve->ui8Size;

  // Set the PKA function to ECC-MULT and start the operation.
  REG((PKA_FUNCTION)) = 0x0000D000;

  // Enable Interrupt
  if(process != NULL) {
    pka_register_process_notification(process);
    nvic_interrupt_unpend(NVIC_INT_PKA);
    nvic_interrupt_enable(NVIC_INT_PKA);
  }

  return (PKA_STATUS_SUCCESS);
}
/*---------------------------------------------------------------------------*/
uint8_t PKAECCMultGenPtGetResult(ec_point_t* ptOutEcPt,
                                 uint32_t ui32ResVectorLoc) {

  int i;
  uint32_t regMSWVal;
  uint32_t addr;
  uint32_t len;

  // Check for the arguments.
  ASSERT(NULL != ptOutEcPt);
  ASSERT(NULL != ptOutEcPt->pui32X);
  ASSERT(NULL != ptOutEcPt->pui32Y);
  ASSERT(ui32ResVectorLoc > PKA_RAM_BASE);
  ASSERT(ui32ResVectorLoc < (PKA_RAM_BASE + PKA_RAM_SIZE));

  // Verify that the operation is completed.
  if((REG(PKA_FUNCTION) & PKA_FUNCTION_RUN) != 0) {
    return (PKA_STATUS_OPERATION_INPRG);
  }

  // Disable Interrupt
  nvic_interrupt_disable(NVIC_INT_PKA);
  pka_register_process_notification(NULL);

  if(REG(PKA_SHIFT) == 0x00000000) {
    // Get the MSW register value.
    regMSWVal = REG(PKA_MSW);

    // Check to make sure that the result vector is not all zeroes.
    if(regMSWVal & PKA_MSW_RESULT_IS_ZERO) {
      return (PKA_STATUS_RESULT_0);
    }

    // Get the length of the result.
    len = ((regMSWVal & PKA_MSW_MSW_ADDRESS_M) + 1)
        - ((ui32ResVectorLoc - PKA_RAM_BASE) >> 2);

    addr = ui32ResVectorLoc;

    // Copy the x co-ordinate value of the result from vector D into the
    // EC point.
    for(i = 0; i < len; i++) {
      ptOutEcPt->pui32X[i] = REG((addr + 4 * i));
    }

    addr += 4 * (i + 2 + len % 2);

    // Copy the y co-ordinate value of the result from vector D into the
    // EC point.
    for(i = 0; i < len; i++) {
      ptOutEcPt->pui32Y[i] = REG((addr + 4 * i));
    }

    return (PKA_STATUS_SUCCESS);
  } else {
    return (PKA_STATUS_FAILURE);
  }
}
/*---------------------------------------------------------------------------*/
uint8_t PKAECCAddStart(ec_point_t* ptEcPt1, ec_point_t* ptEcPt2,
                       ecc_curve_info_t* ptCurve, uint32_t* pui32ResultVector,
                       struct process *process) {

  uint8_t extraBuf;
  uint32_t offset;
  int i;

  // Check for the arguments.
  ASSERT(NULL != ptEcPt1);
  ASSERT(NULL != ptEcPt1->pui32X);
  ASSERT(NULL != ptEcPt1->pui32Y);
  ASSERT(NULL != ptEcPt2);
  ASSERT(NULL != ptEcPt2->pui32X);
  ASSERT(NULL != ptEcPt2->pui32Y);
  ASSERT(NULL != ptCurve);
  ASSERT(NULL != pui32ResultVector);

  offset = 0;

  // Make sure no operation is in progress.
  if((REG(PKA_FUNCTION) & PKA_FUNCTION_RUN) != 0) {
    return (PKA_STATUS_OPERATION_INPRG);
  }

  // Calculate the extra buffer requirement.
  extraBuf = 2 + ptCurve->ui8Size % 2;

  // Update the A ptr with the offset address of the PKA RAM location
  // where the first ecPt will be stored.
  REG(PKA_APTR) = offset >> 2;

  // Load the x co-ordinate value of the first EC point in PKA RAM.
  for(i = 0; i < ptCurve->ui8Size; i++) {
    REG((PKA_RAM_BASE + offset + 4 * i)) = ptEcPt1->pui32X[i];
  }

  // Determine the offset in PKA RAM for the next data.
  offset += 4 * (i + extraBuf);

  // Load the y co-ordinate value of the first EC point in PKA RAM.
  for(i = 0; i < ptCurve->ui8Size; i++) {
    REG((PKA_RAM_BASE + offset + 4 * i)) = ptEcPt1->pui32Y[i];
  }

  // Determine the offset in PKA RAM for the next data.
  offset += 4 * (i + extraBuf);

  // Update the B ptr with the offset address of the PKA RAM location
  // where the curve parameters will be stored.
  REG(PKA_BPTR) = offset >> 2;

  // Write curve parameter 'p' as 1st part of vector B
  for(i = 0; i < ptCurve->ui8Size; i++) {
    REG((PKA_RAM_BASE + offset + 4 * i)) = (uint32_t) ptCurve->pui32Prime[i];
  }

  // Determine the offset in PKA RAM for the next data.
  offset += 4 * (i + extraBuf);

  // Write curve parameter 'a'.
  for(i = 0; i < ptCurve->ui8Size; i++) {
    REG((PKA_RAM_BASE + offset + 4 * i)) = (uint32_t) ptCurve->pui32A[i];
  }

  // Determine the offset in PKA RAM for the next data.
  offset += 4 * (i + extraBuf);

  // Update the C ptr with the offset address of the PKA RAM location
  // where the ecPt2 will be stored.
  REG(PKA_CPTR) = offset >> 2;

  // Load the x co-ordinate value of the second EC point in PKA RAM.
  for(i = 0; i < ptCurve->ui8Size; i++) {
    REG((PKA_RAM_BASE + offset + 4 * i)) = ptEcPt2->pui32X[i];
  }

  // Determine the offset in PKA RAM for the next data.
  offset += 4 * (i + extraBuf);

  // Load the y co-ordinate value of the second EC point in PKA RAM.
  for(i = 0; i < ptCurve->ui8Size; i++) {
    REG((PKA_RAM_BASE + offset + 4 * i)) = ptEcPt2->pui32Y[i];
  }

  // Determine the offset in PKA RAM for the next data.
  offset += 4 * (i + extraBuf);

  // Copy the result vector location.
  *pui32ResultVector = PKA_RAM_BASE + offset;

  // Load D ptr with the result location in PKA RAM.
  REG(PKA_DPTR) = offset >> 2;

  // Load length registers.
  REG(PKA_BLENGTH) = ptCurve->ui8Size;

  // Set the PKA Function to ECC-ADD and start the operation.
  REG((PKA_FUNCTION)) = 0x0000B000;

  // Enable Interrupt
  if(process != NULL) {
    pka_register_process_notification(process);
    nvic_interrupt_unpend(NVIC_INT_PKA);
    nvic_interrupt_enable(NVIC_INT_PKA);
  }

  return (PKA_STATUS_SUCCESS);
}
/*---------------------------------------------------------------------------*/
uint8_t PKAECCAddGetResult(ec_point_t* ptOutEcPt, uint32_t ui32ResVectorLoc) {
  uint32_t regMSWVal;
  uint32_t addr;
  int i;
  uint32_t len;

  // Check for the arguments.
  ASSERT(NULL != ptOutEcPt);
  ASSERT(NULL != ptOutEcPt->pui32X);
  ASSERT(NULL != ptOutEcPt->pui32Y);
  ASSERT(ui32ResVectorLoc > PKA_RAM_BASE);
  ASSERT(ui32ResVectorLoc < (PKA_RAM_BASE + PKA_RAM_SIZE));

  if((REG(PKA_FUNCTION) & PKA_FUNCTION_RUN) != 0) {
    return (PKA_STATUS_OPERATION_INPRG);
  }

  // Disable Interrupt
  nvic_interrupt_disable(NVIC_INT_PKA);
  pka_register_process_notification(NULL);

  if(REG(PKA_SHIFT) == 0x00000000) {
    // Get the MSW register value.
    regMSWVal = REG(PKA_MSW);

    // Check to make sure that the result vector is not all zeroes.
    if(regMSWVal & PKA_MSW_RESULT_IS_ZERO) {
      return (PKA_STATUS_RESULT_0);
    }

    // Get the length of the result.
    len = ((regMSWVal & PKA_MSW_MSW_ADDRESS_M) + 1)
        - ((ui32ResVectorLoc - PKA_RAM_BASE) >> 2);

    addr = ui32ResVectorLoc;

    // Copy the x co-ordinate value of result from vector D into the
    // the output EC Point.
    for(i = 0; i < len; i++) {
      ptOutEcPt->pui32X[i] = REG((addr + 4 * i));
    }

    addr += 4 * (i + 2 + len % 2);

    // Copy the y co-ordinate value of result from vector D into the
    // the output EC Point.
    for(i = 0; i < len; i++) {
      ptOutEcPt->pui32Y[i] = REG((addr + 4 * i));
    }

    return (PKA_STATUS_SUCCESS);
  } else {
    return (PKA_STATUS_FAILURE);
  }
}

/** @} */

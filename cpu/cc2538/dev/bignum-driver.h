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
 * \addtogroup cc2538-pka
 * @{
 *
 * \defgroup cc2538-bignum cc2538 BigNum math function driver
 *
 * Driver for the cc2538 BigNum math functions of the PKC engine
 * @{
 *
 * \file
 * Header file for the cc2538 BigNum driver
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
#ifndef BIGNUM_DRIVER_H_
#define BIGNUM_DRIVER_H_

#include "contiki.h"
#include "pka.h"

#include <stdint.h>

/** @} */
/*---------------------------------------------------------------------------*/
/** \name BigNum functions
 *  \note Not all sequencer functions are implemented in this driver
 *        look at the CC2538 manual for a complete list.
 * @{
 */

/**
 * \brief Helper function to print big numbers
 */
void printNumber(const uint32_t *x, int numberLength);

/** \brief Starts the big number modulus operation.
 *
 * \param pui32BNum is the pointer to the big number on which modulo operation
 *        needs to be carried out.
 * \param ui8BNSize is the size of the big number \sa pui32BNum in 32-bit
 *        word.
 * \param pui32Modulus is the pointer to the divisor.
 * \param ui8ModSize is the size of the divisor \sa pui32Modulus.
 * \param pui32ResultVector is the pointer to the result vector location
 *        which will be set by this function.
 * \param process Process to be polled upon completion of the
 *        operation, or \c NULL
 *
 * This function starts the modulo operation on the big num \sa pui32BNum
 * using the divisor \sa pui32Modulus.  The PKA RAM location where the result
 * will be available is stored in \sa pui32ResultVector.
 *
 *\return Returns:
 * - \b PKA_STATUS_SUCCESS if successful in starting the operation.
 * - \b PKA_STATUS_OPERATION_INPRG, if the PKA hw module is busy doing
 *      some other operation.
 */
extern uint8_t PKABigNumModStart(uint32_t* pui32BNum, uint8_t ui8BNSize,
                                 uint32_t* pui32Modulus, uint8_t ui8ModSize,
                                 uint32_t* pui32ResultVector,
                                 struct process *process);

/** \brief Gets the result of the big number modulus operation.
 *
 * \param pui32ResultBuf is the pointer to buffer where the result needs to
 *        be stored.
 * \param ui8Size is the size of the provided buffer in 32 bit size word.
 * \param ui32ResVectorLoc is the address of the result location which
 *        was provided by the start function \sa PKABigNumModStart().
 *
 * This function gets the result of the big number modulus operation which was
 * previously started using the function \sa PKABigNumModStart().
 *
 * \return Returns:
 * - \b PKA_STATUS_SUCCESS if successful.
 * - \b PKA_STATUS_OPERATION_INPRG, if the PKA hw module is busy doing
 *      the operation.
 * - \b PKA_STATUS_RESULT_0 if the result is all zeroes.
 * - \b PKA_STATUS_BUF_UNDERFLOW, if the \e ui8Size is less than the length
 *      of the result.
 */
extern uint8_t PKABigNumModGetResult(uint32_t* pui32ResultBuf,
                                     uint8_t ui8Size,
                                     uint32_t ui32ResVectorLoc);

/** \brief Starts the comparison of two big numbers.
 *
 * \param pui32BNum1 is the pointer to the first big number.
 * \param pui32BNum2 is the pointer to the second big number.
 * \param ui8Size is the size of the big number in 32 bit size word.
 * \param process Process to be polled upon completion of the
 *        operation, or \c NULL
 *
 * This function starts the comparison of two big numbers pointed by
 * \e pui32BNum1 and \e pui32BNum2.
 * Note this function expects the size of the two big numbers equal.
 *
 *\return Returns:
 * - \b PKA_STATUS_SUCCESS if successful in starting the operation.
 * - \b PKA_STATUS_OPERATION_INPRG, if the PKA hw module is busy doing
 *      some other operation.
 */
extern uint8_t PKABigNumCmpStart(uint32_t* pui32BNum1, uint32_t* pui32BNum2,
                                 uint8_t ui8Size, struct process *process);

/** \brief Gets the result of the comparison operation of two big numbers.
 *
 * This function provides the results of the comparison of two big numbers
 * which was started using the \sa PKABigNumCmpStart().
 *
 * \return Returns:
 * - \b PKA_STATUS_OPERATION_INPRG if the operation is in progress.
 * - \b PKA_STATUS_SUCCESS if the two big numbers are equal.
 * - \b PKA_STATUS_A_GR_B  if the first number is greater than the second.
 * - \b PKA_STATUS_A_LT_B if the first number is less than the second.
 */
extern uint8_t PKABigNumCmpGetResult(void);

/** \brief Starts the big number inverse modulo operation.
 *
 * \param pui32BNum is the pointer to the buffer containing the big number
 *        (dividend).
 * \param ui8BNSize is the size of the \e pui32BNum in 32 bit word.
 * \param pui32Modulus is the pointer to the buffer containing the divisor.
 * \param ui8Size is the size of the divisor in 32 bit word.
 * \param pui32ResultVector is the pointer to the result vector location
 *        which will be set by this function.
 * \param process Process to be polled upon completion of the
 *        operation, or \c NULL
 *
 * This function starts the the inverse modulo operation on \e pui32BNum
 * using the divisor \e pui32Modulus.
 *
 *\return Returns:
 * - \b PKA_STATUS_SUCCESS if successful in starting the operation.
 * - \b PKA_STATUS_OPERATION_INPRG, if the PKA hw module is busy doing
 *      some other operation.
 */
extern uint8_t PKABigNumInvModStart(uint32_t* pui32BNum, uint8_t ui8BNSize,
                                    uint32_t* pui32Modulus, uint8_t ui8Size,
                                    uint32_t* pui32ResultVector,
                                    struct process *process);

/** \brief Gets the result of the big number inverse modulo operation.
 *
 * \param pui32ResultBuf is the pointer to buffer where the result needs to be
 *        stored.
 * \param ui8Size is the size of the provided buffer in 32 bit ui8Size
 *        word.
 * \param ui32ResVectorLoc is the address of the result location which
 *        was provided by the start function \sa PKABigNumInvModStart().
 *
 * This function gets the result of the big number inverse modulo operation
 * previously started using the function \sa PKABigNumInvModStart().
 *
 * \return Returns:
 * - \b PKA_STATUS_SUCCESS if the operation is successful.
 * - \b PKA_STATUS_OPERATION_INPRG, if the PKA hw module is busy performing
 *      the operation.
 * - \b PKA_STATUS_RESULT_0 if the result is all zeroes.
 * - \b PKA_STATUS_BUF_UNDERFLOW if the length of the provided buffer is less
 *      then the result.
 */
extern uint8_t PKABigNumInvModGetResult(uint32_t* pui32ResultBuf,
                                        uint8_t ui8Size,
                                        uint32_t ui32ResVectorLoc);

/** \brief Starts the big number multiplication.
 *
 * \param pui32Xplicand is the pointer to the buffer containing the big
 *        number multiplicand.
 * \param ui8XplicandSize is the size of the multiplicand in 32-bit word.
 * \param pui32Xplier is the pointer to the buffer containing the big
 *        number multiplier.
 * \param ui8XplierSize is the size of the multiplier in 32-bit word.
 * \param pui32ResultVector is the pointer to the result vector location
 *        which will be set by this function.
 * \param process Process to be polled upon completion of the
 *        operation, or \c NULL
 *
 * This function starts the multiplication of the two big numbers.
 *
 *\return Returns:
 * - \b PKA_STATUS_SUCCESS if successful in starting the operation.
 * - \b PKA_STATUS_OPERATION_INPRG, if the PKA hw module is busy doing
 *      some other operation.
 */
extern uint8_t PKABigNumMultiplyStart(uint32_t* pui32Xplicand,
                                      uint8_t ui8XplicandSize,
                                      uint32_t* pui32Xplier,
                                      uint8_t ui8XplierSize,
                                      uint32_t* pui32ResultVector,
                                      struct process *process);

/** \brief Gets the results of the big number multiplication.
 *
 * \param pui32ResultBuf is the pointer to buffer where the result needs to be
 *        stored.
 * \param pui32Len is the address of the variable containing the length of the
 *        buffer.  After the operation, the actual length of the resultant is
 *        stored at this address.
 * \param ui32ResVectorLoc is the address of the result location which
 *        was provided by the start function \sa PKABigNumMultiplyStart().
 *
 * This function gets the result of the multiplication of two big numbers
 * operation previously started using the function \sa
 * PKABigNumMultiplyStart().
 *
 * \return Returns:
 * - \b PKA_STATUS_SUCCESS if the operation is successful.
 * - \b PKA_STATUS_OPERATION_INPRG, if the PKA hw module is busy performing
 *      the operation.
 * - \b PKA_STATUS_RESULT_0 if the result is all zeroes.
 * - \b PKA_STATUS_FAILURE if the operation is not successful.
 * - \b PKA_STATUS_BUF_UNDERFLOW if the length of the provided buffer is less
 *      then the length of the result.
 */
extern uint8_t PKABigNumMultGetResult(uint32_t* pui32ResultBuf,
                                      uint32_t* pui32Len,
                                      uint32_t ui32ResVectorLoc);

/** \brief Starts the addition of two big number.
 *
 * \param pui32BN1 is the pointer to the buffer containing the first
 *        big mumber.
 * \param ui8BN1Size is the size of the first big number in 32-bit word.
 * \param pui32BN2 is the pointer to the buffer containing the second
 *        big number.
 * \param ui8BN2Size is the size of the second big number in 32-bit word.
 * \param pui32ResultVector is the pointer to the result vector location
 *        which will be set by this function.
 * \param process Process to be polled upon completion of the
 *        operation, or \c NULL
 *
 * This function starts the addition of the two big numbers.
 *
 *\return Returns:
 * - \b PKA_STATUS_SUCCESS if successful in starting the operation.
 * - \b PKA_STATUS_OPERATION_INPRG, if the PKA hw module is busy doing
 *      some other operation.
 */
extern uint8_t PKABigNumAddStart(uint32_t* pui32BN1, uint8_t ui8BN1Size,
                                 uint32_t* pui32BN2, uint8_t ui8BN2Size,
                                 uint32_t* pui32ResultVector,
                                 struct process *process);

/** \brief Gets the result of the addition operation on two big number.
 *
 * \param pui32ResultBuf is the pointer to buffer where the result
 *        needs to be stored.
 * \param pui32Len is the address of the variable containing the length of
 *        the buffer.  After the operation the actual length of the
 *        resultant is stored at this address.
 * \param ui32resVectorLoc is the address of the result location which
 *        was provided by the start function \sa PKABigNumAddStart().
 *
 * This function gets the result of the addition operation on two big numbers,
 * previously started using the function \sa PKABigNumAddStart().
 *
 * \return Returns:
 * - \b PKA_STATUS_SUCCESS if the operation is successful.
 * - \b PKA_STATUS_OPERATION_INPRG, if the PKA hw module is busy performing
 *      the operation.
 * - \b PKA_STATUS_RESULT_0 if the result is all zeroes.
 * - \b PKA_STATUS_FAILURE if the operation is not successful.
 * - \b PKA_STATUS_BUF_UNDERFLOW if the length of the provided buffer is less
 *      then the length of the result.
 */
extern uint8_t PKABigNumAddGetResult(uint32_t* pui32ResultBuf,
                                     uint32_t* pui32Len,
                                     uint32_t ui32resVectorLoc);

/** \brief Starts the substract of two big number.
 *
 * \param pui32BN1 is the pointer to the buffer containing the first
 *        big mumber.
 * \param ui8BN1Size is the size of the first big number in 32-bit word.
 * \param pui32BN2 is the pointer to the buffer containing the second
 *        big number.
 * \param ui8BN2Size is the size of the second big number in 32-bit word.
 * \param pui32ResultVector is the pointer to the result vector location
 *        which will be set by this function.
 * \param process Process to be polled upon completion of the
 *        operation, or \c NULL
 *
 * This function starts the substraction of the two big numbers.
 *
 *\return Returns:
 * - \b PKA_STATUS_SUCCESS if successful in starting the operation.
 * - \b PKA_STATUS_OPERATION_INPRG, if the PKA hw module is busy doing
 *      some other operation.
 *
 */
extern uint8_t PKABigNumSubtractStart(uint32_t* pui32BN1, uint8_t ui8BN1Size,
                                      uint32_t* pui32BN2, uint8_t ui8BN2Size,
                                      uint32_t* pui32ResultVector,
                                      struct process *process);

/** \brief Gets the result of big number subtract.
 *
 * \param pui32ResultBuf is the pointer to store the result of subtraction.
 * \param pui32ResVectorLoc is the address of the result location which
 *        was provided by the start function PKABigNumSubtractStart().
 *
 * This function gets the result of PKABigNumSubtractStart().
 *
 * \return Returns:
 * - \b PKA_STATUS_SUCCESS if the operation is successful.
 * - \b PKA_STATUS_OPERATION_INPRG, if the PKA hw module is busy performing
 *      the operation.
 * - \b PKA_STATUS_RESULT_0 if the result is all zeroes.
 * - \b PKA_STATUS_FAILURE if the operation is not successful.
 */
extern uint8_t PKABigNumSubtractGetResult(uint32_t* pui32ResultBuf, uint32_t* pui32Len,
                                          uint32_t ui32ResVectorLoc);


/** \brief Starts the big number moduluar Exponentiation operation.
 *
 * \param pui32BNum is the pointer to the Exponent on which moduluar Exponentiation operation
 *        needs to be carried out.
 * \param ui8BNSize is the size of the the Exponent number pui32BNum in 32-bit
 *        word.
 * \param pui32Modulus is the pointer to the divisor.
 * \param ui8ModSize is the size of the divisor pui32Modulus.
 *
 * \param pui32Base is the pointer to the Base.
 * \param ui8BaseSize is the size of the divisor pui32Base.
 *
 * \param pui32ResultVector is the pointer to the result vector location
 *        which will be set by this function.
 * \param process Process to be polled upon completion of the
 *        operation, or \c NULL
 *
 * This function starts the moduluar Exponentiation operation on the base num pui32Base
 * using the Exponent pui32BNum and the Modulus num pui32Modulus.  The PKA RAM location where the result
 * will be available is stored in \sa pui32ResultVector.
 * IMPORTANT = Modulus and Based should have buffers of the same length!
 *
 *\return Returns:
 * - \b PKA_STATUS_SUCCESS if successful in starting the operation.
 * - \b PKA_STATUS_OPERATION_INPRG, if the PKA hw module is busy doing
 *      some other operation.
 */
extern uint8_t PKABigNumExpModStart(uint32_t* pui32BNum, uint8_t ui8BNSize,
                                    uint32_t* pui32Modulus, uint8_t ui8ModSize,
                                    uint32_t* pui32Base, uint8_t ui8BaseSize,
                                    uint32_t* pui32ResultVector,
                                    struct process *process);

/** \brief Gets the result of the big number modulus operation result.
 *
 * \param pui32ResultBuf is the pointer to buffer where the result needs to
 *        be stored.
 * \param ui8Size is the size of the provided buffer in 32 bit size word.
 * \param ui32ResVectorLoc is the address of the result location which
 *        was provided by the start function \sa PKABigNumExpModStart().
 *
 * This function gets the result of the big number modulus operation which was
 * previously started using the function \sa PKABigNumExpModStart().
 *
 * \return Returns:
 * - \b PKA_STATUS_SUCCESS if successful.
 * - \b PKA_STATUS_OPERATION_INPRG, if the PKA hw module is busy doing
 *      the operation.
 * - \b PKA_STATUS_RESULT_0 if the result is all zeroes.
 * - \b PKA_STATUS_BUF_UNDERFLOW, if the \e ui8Size is less than the length
 *      of the result.
 *
 *      notes for this function:
 *      1)0<ui8BNSize<=Max_Len,1<ui8ModSize<=Max_Len
 *      2)pui32Modulus must be odd and pui32Modulus>232
 *      3)pui32Base<pui32Modulus
 */
extern uint8_t PKABigNumExpModGetResult(uint32_t* pui32ResultBuf,
                                        uint8_t ui8Size,
                                        uint32_t ui32ResVectorLoc);

/** \brief Starts the big number Divide.
 *
 * \param pui32Xdividend is the pointer to the buffer containing the big
 *        number dividend.
 * \param ui8XdividendSize is the size of the dividend in 32-bit word.
 * \param pui32Xdivisor is the pointer to the buffer containing the big
 *        number divisor.
 * \param ui8XdivisorSize is the size of the divisor in 32-bit word.
 * \param pui32ResultVector is the pointer to the result vector location
 *        which will be set by this function.
 * \param process Process to be polled upon completion of the
 *        operation, or \c NULL
 *
 * This function starts the divide of the two big numbers.
 *
 *\return Returns:
 * - \b PKA_STATUS_SUCCESS if successful in starting the operation.
 * - \b PKA_STATUS_OPERATION_INPRG, if the PKA hw module is busy doing
 *      some other operation.
 */
extern uint8_t PKABigNumDivideStart(uint32_t* pui32Xdividend,
                                    uint8_t ui8XdividendSize,
                                    uint32_t* pui32Xdivisor,
                                    uint8_t ui8XdivisorSize,
                                    uint32_t* pui32ResultVector,
                                    struct process *process);

/** \brief Gets the results of the big number Divide.
 *
 * \param pui32ResultBuf is the pointer to buffer where the result needs to be
 *        stored.
 * \param pui32Len is the address of the variable containing the length of the
 *        buffer.  After the operation, the actual length of the resultant is
 *        stored at this address.
 * \param ui32ResVectorLoc is the address of the result location which
 *        was provided by the start function \sa PKABigNumMultiplyStart().
 *
 * This function gets the result of the Divide of two big numbers
 * operation previously started using the function \sa
 * PKABigNumDivideStart().
 *
 * \return Returns:
 * - \b PKA_STATUS_SUCCESS if the operation is successful.
 * - \b PKA_STATUS_OPERATION_INPRG, if the PKA hw module is busy performing
 *      the operation.
 * - \b PKA_STATUS_RESULT_0 if the result is all zeroes.
 * - \b PKA_STATUS_FAILURE if the operation is not successful.
 * - \b PKA_STATUS_BUF_UNDERFLOW if the length of the provided buffer is less
 *      then the length of the result.
 */
extern uint8_t PKABigNumDivideGetResult(uint32_t* pui32ResultBuf,
                                        uint32_t* pui32Len,
                                        uint32_t ui32ResVectorLoc);

/** @} */

#endif /* BIGNUM_DRIVER_H_ */

/**
 * @}
 * @}
 */

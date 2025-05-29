#ifndef ANTI_ANALYSIS_H_
#define ANTI_ANALYSIS_H_

#include "../../common.h"

/**
 * @brief Detects and mitigates analysis techniques.
 *
 * This function implements various anti-analysis techniques to detect or evade debugging,
 * sandboxing, and other forms of dynamic analysis. It can introduce delays or alter execution 
 * behavior to make analysis more difficult.
 *
 * @param dwMilliSeconds The duration in milliseconds for which the delay function will last.
 *
 * @return TRUE if the anti-analysis measures were successfully and the program can continue, FALSE otherwise.
 * 
 * @name Anti Analysis
 * @flags ANTI_ANALYSIS_ENABLED
 */
BOOL AntiAnalysis(DWORD dwMilliSeconds);

/**
 * @brief Delays execution using the NtDelayExecution system call.
 *
 * This function introduces a delay in execution by leveraging the NtDelayExecution API,
 * which puts the calling thread into a suspended state for the specified duration.
 *
 * @param ftMinutes The duration of the delay in minutes.
 *
 * @return TRUE if the delay was successfully applied, FALSE otherwise.
 */
BOOL DelayExecutionVia_NtDE(FLOAT ftMinutes);

/**
 * @brief Logs mouse clicks performed by the user.
 *
 * This function captures and logs mouse click events, tracking user interaction with the system.
 * It can be used for monitoring purposes or detecting user activity.
 *
 * @return TRUE if the mouse click events were successfully logged, FALSE otherwise.
 */
BOOL MouseClicksLogger();

#endif
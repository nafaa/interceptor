/*
 * ExceptionHandler.h
 *
 *  Created on: 16 oct. 2020
 *      Author: nafaa
 */

#ifndef EXCEPTIONHANDLER_H_
#define EXCEPTIONHANDLER_H_

#include <string>
using namespace std;
class ExceptionHanlder
{


 public:
	ExceptionHanlder(const string& msg) : reason(msg) {}
   ~ExceptionHanlder() {}

    string getMessage() const {return(reason);}
 private:
	std::string reason;
};


#endif /* EXCEPTIONHANDLER_H_ */

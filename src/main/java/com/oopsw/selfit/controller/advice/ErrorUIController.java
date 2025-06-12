package com.oopsw.selfit.controller.advice;

import org.springframework.boot.web.servlet.error.ErrorController;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

import jakarta.servlet.RequestDispatcher;
import jakarta.servlet.http.HttpServletRequest;

// @Controller
public class ErrorUIController implements ErrorController {

	@RequestMapping("/error")
	public String handleError(HttpServletRequest request, Exception e) {
		e.printStackTrace();
		int status = (int)request.getAttribute(RequestDispatcher.ERROR_STATUS_CODE);

		if (status == HttpStatus.NOT_FOUND.value()) {
			return "error/404";
		}

		return "error/500";
	}

}

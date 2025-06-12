package com.oopsw.selfit.controller.advice;

import java.net.BindException;
import java.sql.SQLSyntaxErrorException;
import java.time.LocalDateTime;
import java.util.stream.Collectors;

import org.springframework.dao.DataAccessException;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;

import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@RestControllerAdvice
public class RestControllerExceptionHandler {

	private ResponseEntity<CustomErrorResponse> buildResponse(HttpServletRequest request, HttpStatus status,
		String message) {
		CustomErrorResponse response = CustomErrorResponse.builder()
			.path(request.getRequestURI())
			.message(message)
			.timestamp(LocalDateTime.now())
			.build();
		return ResponseEntity.status(status).body(response);
	}

	@ExceptionHandler(MethodArgumentNotValidException.class)
	public ResponseEntity<CustomErrorResponse> handleValidationException(MethodArgumentNotValidException e,
		HttpServletRequest request) {
		log.warn("Validation failed: {}", e.getMessage());
		String message = e.getBindingResult()
			.getFieldErrors()
			.stream()
			.map(error -> error.getField() + ": " + error.getDefaultMessage())
			.collect(Collectors.joining(", "));
		return buildResponse(request, HttpStatus.BAD_REQUEST, "유효성 검증 실패: " + message);
	}

	@ExceptionHandler({BindException.class, HttpMessageNotReadableException.class,
		MethodArgumentTypeMismatchException.class})
	public ResponseEntity<CustomErrorResponse> handleBadRequestExceptions(Exception e, HttpServletRequest request) {
		log.warn("Bad request: {}", e.getMessage());
		return buildResponse(request, HttpStatus.BAD_REQUEST, "잘못된 요청입니다. 요청 형식이나 파라미터를 확인하세요.");
	}

	@ExceptionHandler({IllegalArgumentException.class, NullPointerException.class})
	public ResponseEntity<CustomErrorResponse> handleIllegalOrNull(Exception e, HttpServletRequest request) {
		log.warn("Illegal or null exception: {}", e.getMessage(), e);
		return buildResponse(request, HttpStatus.BAD_REQUEST, "요청 처리 중 문제가 발생했습니다. error: " + e.getMessage());
	}

	@ExceptionHandler(HttpRequestMethodNotSupportedException.class)
	public ResponseEntity<CustomErrorResponse> handleMethodNotAllowed(HttpRequestMethodNotSupportedException e,
		HttpServletRequest request) {
		log.warn("Method not allowed: {}", e.getMessage());
		return buildResponse(request, HttpStatus.METHOD_NOT_ALLOWED, "허용되지 않은 HTTP 메서드입니다.");
	}

	@ExceptionHandler(DataIntegrityViolationException.class)
	public ResponseEntity<CustomErrorResponse> handleDataIntegrityViolation(DataIntegrityViolationException e,
		HttpServletRequest request) {
		log.error("Data integrity violation: {}", e.getMessage(), e);
		return buildResponse(request, HttpStatus.CONFLICT, "데이터 무결성 오류가 발생했습니다. (중복 또는 제약 조건 위반): " + e.getMessage());
	}

	@ExceptionHandler(SQLSyntaxErrorException.class)
	public ResponseEntity<CustomErrorResponse> handleSqlSyntaxError(SQLSyntaxErrorException e,
		HttpServletRequest request) {
		log.error("SQL syntax error: {}", e.getMessage(), e);
		return buildResponse(request, HttpStatus.INTERNAL_SERVER_ERROR, "서버 오류: 잘못된 SQL 문입니다.");
	}

	@ExceptionHandler(DataAccessException.class)
	public ResponseEntity<CustomErrorResponse> handleDataAccess(DataAccessException e, HttpServletRequest request) {
		log.error("Data access error: {}", e.getMessage(), e);
		return buildResponse(request, HttpStatus.INTERNAL_SERVER_ERROR, "서버 오류: 데이터베이스 처리 중 문제가 발생했습니다.");
	}

}


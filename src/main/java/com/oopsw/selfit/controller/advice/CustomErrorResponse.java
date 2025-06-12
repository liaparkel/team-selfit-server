package com.oopsw.selfit.controller.advice;

import java.time.LocalDateTime;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Builder
@AllArgsConstructor
public class CustomErrorResponse {
	private String message;
	private String path;
	private LocalDateTime timestamp;
}

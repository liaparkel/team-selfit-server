package com.oopsw.selfit.controller;

import java.util.List;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.oopsw.selfit.dto.Board;
import com.oopsw.selfit.service.BoardService;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@RestController
@RequestMapping("/api")
public class CategoryRestController {

	private final BoardService boardService;

	@GetMapping("/category")
	public ResponseEntity<List<Board>> getCategoryList() {

		return ResponseEntity.ok(boardService.getCategory());
	}

}

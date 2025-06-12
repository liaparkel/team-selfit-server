package com.oopsw.selfit.controller;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

import jakarta.servlet.http.HttpSession;

@Controller
public class UIController {

	//account
	@GetMapping("/account/login")
	public String login() {
		return "account/login";
	}

	@GetMapping("/account/signup")
	public String signup() {
		return "account/signup";
	}

	@GetMapping("/account/signup-oauth")
	public String signupOauth(HttpSession session, Model model) {
		String email = (String)session.getAttribute("email");
		String name = (String)session.getAttribute("name");
		model.addAttribute("email", email);
		model.addAttribute("name", name);
		if (email == null) {
			return "/account/login";
		}

		return "/account/signup-oauth";
	}

	@GetMapping("/account/mypage")
	public String mypage() {
		return "account/mypage";
	}

	@GetMapping("/account/mypage-update")
	public String mypageUpdate() {
		return "account/mypage-update";
	}

	//dashboard
	@GetMapping("/dashboard")
	public String dashboard() {
		return "dashboard/dashboard";
	}

	@GetMapping("/dashboard/checklist")
	public String checklist() {
		return "dashboard/checklist";
	}

	@GetMapping("/dashboard/food")
	public String food() {
		return "dashboard/food";
	}

	@GetMapping("/dashboard/exercise")
	public String exercise() {
		return "dashboard/exercise";
	}

	@GetMapping("dashboard/kcal")
	public String kcal() {
		return "dashboard/kcal";
	}

	//board
	@GetMapping("board/list")
	public String boardList() {
		return "board/board";
	}

	@GetMapping("board/detail/{boardId}")
	public String deatail(@PathVariable int boardId, Model model) {
		model.addAttribute("boardId", boardId);
		return "board/boardDetail";
	}

	@GetMapping("board/write")
	public String write() {
		return "board/boardForm";
	}

	@GetMapping("/board/edit/{boardId}")
	public String edit(@PathVariable int boardId, Model model) {
		model.addAttribute("boardId", boardId);
		return "board/boardForm";
	}
}
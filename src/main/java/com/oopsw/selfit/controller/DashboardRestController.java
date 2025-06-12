package com.oopsw.selfit.controller;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.oopsw.selfit.auth.AuthenticatedUser;
import com.oopsw.selfit.dto.Checklist;
import com.oopsw.selfit.dto.Exercise;
import com.oopsw.selfit.dto.ExerciseApi;
import com.oopsw.selfit.dto.Food;
import com.oopsw.selfit.dto.FoodApi;
import com.oopsw.selfit.dto.Member;
import com.oopsw.selfit.service.CheckService;
import com.oopsw.selfit.service.DashboardService;
import com.oopsw.selfit.service.ExerciseApiService;
import com.oopsw.selfit.service.FoodApiService;
import com.oopsw.selfit.service.ExerciseInfoService;
import com.oopsw.selfit.service.FoodInfoService;

import lombok.RequiredArgsConstructor;
import reactor.core.publisher.Mono;

@RestController
@RequestMapping("/api/dashboard")
@RequiredArgsConstructor
public class DashboardRestController {
	private final DashboardService dashboardService;
	private final FoodInfoService foodInfoService;
	private final CheckService checkService;
	private final ExerciseInfoService exerciseInfoService;
	private final FoodApiService foodApiService;
	private final ExerciseApiService exerciseApiService;

	@PostMapping("/food/openSearch")
	public Mono<List<FoodApi>> openFoodSearch(@RequestBody Map<String, Object> payload) {
		String keyword = (String) payload.get("keyword");
		int pageNo   = ((Number) payload.get("pageNo")).intValue();
		int numOfRows= ((Number) payload.get("numOfRows")).intValue();
		return foodApiService.getFoodByNameLike(keyword, pageNo, numOfRows);
	}

	@PostMapping("/exercise/openSearch")
	public Mono<List<ExerciseApi>> openExerciseSearch(@RequestBody Map<String, Object> payload) {
		String keyword = (String) payload.get("keyword");
		int pageNo   = ((Number) payload.get("pageNo")).intValue();
		int numOfRows= ((Number) payload.get("numOfRows")).intValue();
		return exerciseApiService.getExercisesByNameLike(keyword, pageNo, numOfRows);
	}


	@PostMapping("/bmr")
	public ResponseEntity<Map<String, Integer>> getBmr(@RequestBody Member member, @AuthenticationPrincipal AuthenticatedUser loginUser) {
		member.setMemberId(loginUser.getMemberId());
		return ResponseEntity.ok(Map.of("bmr", dashboardService.getBmr(member.getMemberId())));
	}

	@PostMapping("/food/kcal")
	public ResponseEntity<Food> getIntakeKcal(@RequestBody Food food, @AuthenticationPrincipal AuthenticatedUser loginUser) {
		food.setMemberId(loginUser.getMemberId());
		return ResponseEntity.ok(dashboardService.getIntakeKcal(food));
	}

	@PostMapping("/exercise/kcal")
	public ResponseEntity<Exercise> getExerciseKcal(@RequestBody Exercise exercise, @AuthenticationPrincipal AuthenticatedUser loginUser) {
		exercise.setMemberId(loginUser.getMemberId());
		return ResponseEntity.ok(dashboardService.getExerciseKcal(exercise));
	}

	@PostMapping("/food/kcal/year")
	public ResponseEntity<List<Food>> getYearIntakeKcal(@RequestBody Map<String, Object> param, @AuthenticationPrincipal AuthenticatedUser loginUser) {
		HashMap<String, Object> map = new HashMap<>();
		map.put("memberId", loginUser.getMemberId());
		map.put("intakeYear", ((Number)param.get("intakeYear")).intValue());

		return ResponseEntity.ok(dashboardService.getYearIntakeKcal(map));
	}

	@PostMapping("/exercise/kcal/year")
	public ResponseEntity<List<Exercise>> getYearExerciseKcal(@RequestBody Map<String, Object> param, @AuthenticationPrincipal AuthenticatedUser loginUser) {
		HashMap<String, Object> map = new HashMap<>();

		map.put("memberId", loginUser.getMemberId());
		map.put("exerciseYear", ((Number)param.get("exerciseYear")).intValue());

		return ResponseEntity.ok(dashboardService.getYearExerciseKcal(map));
	}

	@PostMapping("/food/list")
	public ResponseEntity<Map<String, Integer>> addFoodList(@RequestBody Food food, @AuthenticationPrincipal AuthenticatedUser loginUser) {
		food.setMemberId(loginUser.getMemberId());
		return ResponseEntity.ok(Map.of("foodNoteId", dashboardService.addFoodList(food)));
	}

	@DeleteMapping("/food/list")
	public ResponseEntity<Map<String, Boolean>> removeFoodList(@RequestBody Food food, @AuthenticationPrincipal AuthenticatedUser loginUser) {
		food.setMemberId(loginUser.getMemberId());
		return ResponseEntity.ok(Map.of("success", dashboardService.removeFoodList(food)));
	}

	@PostMapping("/exercise/list")
	public ResponseEntity<Map<String, Integer>> addExerciseList(@RequestBody Exercise exercise, @AuthenticationPrincipal AuthenticatedUser loginUser) {
		exercise.setMemberId(loginUser.getMemberId());
		int noteId = dashboardService.addExerciseList(exercise);
		return ResponseEntity.ok(Map.of("exerciseNoteId", noteId));
	}

	@DeleteMapping("/exercise/list")
	public ResponseEntity<Map<String, Boolean>> removeExerciseList(@RequestBody Exercise exercise, @AuthenticationPrincipal AuthenticatedUser loginUser) {
		exercise.setMemberId(loginUser.getMemberId());
		return ResponseEntity.ok(Map.of("success", dashboardService.removeExerciseList(exercise)));
	}

	@PostMapping("/goal")
	public ResponseEntity<Map<String, String>> getGoal(@RequestBody Member member, @AuthenticationPrincipal AuthenticatedUser loginUser) {
		member.setMemberId(loginUser.getMemberId());
		return ResponseEntity.ok(Map.of("goal", dashboardService.getGoal(member.getMemberId())));
	}

	@PostMapping("/food/kcal/avg/year")
	public ResponseEntity<List<Map<String, Object>>> getYearIntakeAvgAll(@RequestBody Map<String, Integer> param, @AuthenticationPrincipal AuthenticatedUser loginUser) {
		int memberId = loginUser.getMemberId(); //param.get("memberId");
		int intakeYear = param.get("intakeYear");
		return ResponseEntity.ok(dashboardService.getYearIntakeAvgAll(memberId, intakeYear));
	}

	@PostMapping("/exercise/kcal/avg/year")
	public ResponseEntity<List<Map<String, Object>>> getYearExerciseAvgAll(@RequestBody Map<String, Integer> param, @AuthenticationPrincipal AuthenticatedUser loginUser) {
		int memberId = loginUser.getMemberId(); //param.get("memberId");
		int exerciseYear = param.get("exerciseYear");
		return ResponseEntity.ok(dashboardService.getYearExerciseAvgAll(memberId, exerciseYear));
	}

	@PostMapping("/checklist/items")
	public ResponseEntity<List<Checklist>> getCheckList(@RequestBody Checklist checklist, @AuthenticationPrincipal AuthenticatedUser loginUser) {
		checklist.setMemberId(loginUser.getMemberId());
		return ResponseEntity.ok(dashboardService.getCheckList(checklist));
	}

	@PutMapping("/checklist/item")
	public ResponseEntity<Map<String, Boolean>> setCheckItem(@RequestBody Checklist checklist, @AuthenticationPrincipal AuthenticatedUser loginUser) {
		checklist.setMemberId(loginUser.getMemberId());
		return ResponseEntity.ok(Map.of("success", checkService.setCheckItem(checklist)));
	}

	@PutMapping("/checklist/item/check")
	public ResponseEntity<Map<String, Boolean>> setIsCheckItem(@RequestBody Checklist checklist, @AuthenticationPrincipal AuthenticatedUser loginUser) {
		checklist.setMemberId(loginUser.getMemberId());
		return ResponseEntity.ok(Map.of("success", checkService.setIsCheckItem(checklist)));
	}

	@DeleteMapping("/checklist/item")
	public ResponseEntity<Map<String, Boolean>> removeCheckItem(@RequestBody Checklist checklist, @AuthenticationPrincipal AuthenticatedUser loginUser) {
		checklist.setMemberId(loginUser.getMemberId());
		return ResponseEntity.ok(Map.of("success", checkService.removeCheckItem(checklist)));
	}

	@PostMapping("/checklist")
	public ResponseEntity<Map<String, Integer>> addChecklist(@RequestBody Checklist checklist, @AuthenticationPrincipal AuthenticatedUser loginUser) {
		checklist.setMemberId(loginUser.getMemberId());
		return ResponseEntity.ok(Map.of("checklistId", dashboardService.addChecklist(checklist)));
	}

	@DeleteMapping("/checklist")
	public ResponseEntity<Map<String, Boolean>> removeChecklist(@RequestBody Map<String, Integer> body, @AuthenticationPrincipal AuthenticatedUser loginUser) {
		Integer checklistId = body.get("checklistId");
		return ResponseEntity.ok(Map.of("success", dashboardService.removeChecklist(checklistId)));
	}

	@PostMapping("/checklist/item")
	public ResponseEntity<Map<String, Boolean>> addCheckItem(@RequestBody Checklist checklist, @AuthenticationPrincipal AuthenticatedUser loginUser) {
		checklist.setMemberId(loginUser.getMemberId());
		return ResponseEntity.ok(Map.of("success", checkService.addCheckItem(checklist)));
	}

	@DeleteMapping("/food")
	public ResponseEntity<Map<String, Boolean>> removeFoodInfo(@RequestBody Map<String, Integer> foodInfoId) {
		return ResponseEntity.ok(Map.of("success", foodInfoService.removeFood(foodInfoId.get("foodInfoId"))));
	}

	@PutMapping("/food")
	public ResponseEntity<Map<String, Boolean>> setIntake(@RequestBody Map<String, Integer> food) {
		return ResponseEntity.ok(
			Map.of("success", foodInfoService.setIntake(food.get("foodInfoId"), food.get("newIntake"))));
	}

	@PostMapping("/food")
	public ResponseEntity<Map<String, Boolean>> addFoodInfo(@RequestBody Map<String, Object> food) {
		Food f = Food.builder()
			.foodNoteId((int)food.get("foodNoteId"))
			.foodName((String)food.get("foodName"))
			.intake((int)food.get("intake"))
			.unitKcal(((Number)food.get("unitKcal")).intValue())
			.build();
		return ResponseEntity.ok(Map.of("success", foodInfoService.addFoodInfo(f)));
	}

	@PostMapping("/foods")
	public ResponseEntity<List<Food>> getFoodInfos(@RequestBody Map<String, Object> foods, @AuthenticationPrincipal AuthenticatedUser loginUser) {
		Food food = Food.builder()
			.intakeDate((String)foods.get("intakeDate"))
			.memberId(loginUser.getMemberId())
			.build();
		return ResponseEntity.ok(foodInfoService.getFoodInfoList(food));
	}

	@DeleteMapping("/exercise")
	public ResponseEntity<Map<String, Boolean>> removeExerciseInfo(@RequestBody Map<String, Integer> exerciseInfoId) {
		return ResponseEntity.ok(
			Map.of("success", exerciseInfoService.removeExercise(exerciseInfoId.get("exerciseInfoId"))));
	}

	@PutMapping("/exercise")
	public ResponseEntity<Map<String, Boolean>> setExerciseMin(@RequestBody Map<String, Integer> exerciseInfo) {
		return ResponseEntity.ok(Map.of("success",
			exerciseInfoService.setExerciseMin(exerciseInfo.get("exerciseInfoId"), exerciseInfo.get("newMin"))));
	}

	@PostMapping("/exercise")
	public ResponseEntity<Map<String, Boolean>> addExerciseInfo(@RequestBody Map<String, Object> exerciseInfo) {
		Exercise e = Exercise.builder()
			.exerciseNoteId((int)exerciseInfo.get("exerciseNoteId"))
			.exerciseMin((int)exerciseInfo.get("exerciseMin"))
			.exerciseName((String)exerciseInfo.get("exerciseName"))
			.met(((Number)exerciseInfo.get("met")).floatValue())
			.build();
		return ResponseEntity.ok(Map.of("success", exerciseInfoService.addExerciseInfo(e)));
	}

	@PostMapping("/exercises")
	public ResponseEntity<List<Exercise>> getExerciseInfos(@RequestBody Map<String, Object> exercises, @AuthenticationPrincipal AuthenticatedUser loginUser) {
		Exercise exercise = Exercise.builder()
			.exerciseDate((String)exercises.get("exerciseDate"))
			.memberId(loginUser.getMemberId())
			.build();
		return ResponseEntity.ok(exerciseInfoService.getExerciseInfoList(exercise));
	}

}

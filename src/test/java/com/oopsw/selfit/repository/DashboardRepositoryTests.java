package com.oopsw.selfit.repository;

import static org.junit.jupiter.api.Assertions.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.transaction.annotation.Transactional;

import com.oopsw.selfit.dto.Checklist;
import com.oopsw.selfit.dto.Exercise;
import com.oopsw.selfit.dto.Food;
import com.oopsw.selfit.dto.Member;

@Transactional
@SpringBootTest
public class DashboardRepositoryTests {
	@Autowired
	private DashboardRepository dashboardRepository;

	// @Test
	// void testGetFoodWeightYes() {
	// 	// given
	// 	String foodName = "사과";
	//
	// 	// when
	// 	String foodWeight = dashboardRepository.getFoodWeight(foodName);
	//
	// 	// than
	// 	assertEquals("200g", foodWeight);
	// }
	//
	// @Test
	// void testGetFoodWeightNameNotExist() {
	// 	// given
	// 	String foodName = "볼펜";
	//
	// 	// when
	// 	String foodWeight = dashboardRepository.getFoodWeight(foodName);
	//
	// 	// than
	// 	assertNull(foodWeight);
	// }

	@Test
	void testGetBmrYes() {
		// given
		int memberId = 1;

		// when
		Member member = dashboardRepository.getBmr(memberId);

		// than
		assertEquals("남자", member.getGender());
		assertEquals("2000-05-21", member.getBirthday());
		assertEquals(175f, member.getHeight());
		assertEquals(70f, member.getWeight());
	}

	@Test
	void testGetBmrNotExistMemberId() {
		// given
		int memberId = 99999;

		// when
		Member member = dashboardRepository.getBmr(memberId);

		// than
		assertNull(member);
	}

	@Test
	void testGetIntakeKcalYes() {
		// given
		Food request = Food.builder().memberId(1).intakeDate("2025-05-21").build();

		// when
		Food result = dashboardRepository.getIntakeKcal(request);

		// than
		assertNotNull(result.getIntakeSum());
	}

	@Test
	void testGetIntakeKcalNotExistMemberId() {
		// given
		Food request = Food.builder().memberId(99999).intakeDate("2025-05-21").build();

		// when
		Food result = dashboardRepository.getIntakeKcal(request);

		// than
		assertNull(result);
	}

	@Test
	void testGetExerciseKcalYes() {
		// given
		Exercise request = Exercise.builder().memberId(1).exerciseDate("2025-05-21").build();

		// when
		Exercise result = dashboardRepository.getExerciseKcal(request);

		// than
		assertNotNull(result.getExerciseSum());
	}

	@Test
	void testGetExerciseKcalNotExistMemberId() {
		// given
		Exercise request = Exercise.builder().memberId(99999).exerciseDate("2025-05-21").build();

		// when
		Exercise result = dashboardRepository.getExerciseKcal(request);

		// than
		assertNull(result);
	}

	@Test
	void testGetYearIntakeKcalYes() {
		// given
		HashMap<String, Object> map = new HashMap<>();
		map.put("memberId", 1);
		map.put("intakeYear", "2025");

		// when
		List<Food> result = dashboardRepository.getYearIntakeKcal(map);

		// then
		assertFalse(result.isEmpty());
	}

	@Test
	void testGetYearIntakeKcalNotExistMemberId() {
		// given
		HashMap<String, Object> map = new HashMap<>();
		map.put("memberId", 99999);
		map.put("intakeYear", "2025");

		// when
		List<Food> result = dashboardRepository.getYearIntakeKcal(map);

		// then
		assertTrue(result.isEmpty());
	}

	@Test
	void testGetYearExerciseKcalYes() {
		// given
		HashMap<String, Object> map = new HashMap<>();
		map.put("memberId", 1);
		map.put("exerciseYear", "2025");

		// when
		List<Exercise> result = dashboardRepository.getYearExerciseKcal(map);

		// then
		assertFalse(result.isEmpty());
	}

	@Test
	void testGetYearExerciseKcalNotExistMemberId() {
		// given
		HashMap<String, Object> map = new HashMap<>();
		map.put("memberId", 99999);
		map.put("exerciseYear", "2025");

		// when
		List<Exercise> result = dashboardRepository.getYearExerciseKcal(map);

		// then
		assertTrue(result.isEmpty());
	}

	// @Test
	// void testGetIntakeDetailYes() {
	// 	// given
	// 	Food request = Food.builder().memberId(1).intakeDate("2025-05-21").build();
	//
	// 	// when
	// 	List<Food> result = dashboardRepository.getIntakeDetail(request);
	//
	// 	// then
	// 	assertFalse(result.isEmpty());
	// }
	//
	// @Test
	// void testGetIntakeDetailNotExistMemberId() {
	// 	// given
	// 	Food request = Food.builder().memberId(99999).intakeDate("2025-05-21").build();
	//
	// 	// when
	// 	List<Food> result = dashboardRepository.getIntakeDetail(request);
	//
	// 	// then
	// 	assertTrue(result.isEmpty());
	// }
	//
	// @Test
	// void testGetAutoCompleteFoodYes() {
	// 	// given
	// 	String partWord = "유";
	//
	// 	// when
	// 	List<String> result = dashboardRepository.getAutoCompleteFood(partWord);
	//
	// 	// then
	// 	assertFalse(result.isEmpty());
	// }

	// @Test
	// void testGetAutoCompleteFoodInvalidKeyword() {
	// 	// given
	// 	String partWord = "selfit";
	//
	// 	// when
	// 	List<String> result = dashboardRepository.getAutoCompleteFood(partWord);
	//
	// 	// then
	// 	assertTrue(result.isEmpty());
	// }

	@Test
	void testAddFoodListYes() {
		// given
		Food request = Food.builder().memberId(1).intakeDate("2025-06-05").build();

		// when
		int result = dashboardRepository.addFoodList(request);

		// then
		assertEquals(1, result);
	}

	@Test
	void testAddFoodListNotExistMemberId() {
		// given
		Food request = Food.builder().memberId(99999).intakeDate("2025-06-05").build();

		// when & then
		assertThrows(DataIntegrityViolationException.class, () -> {
			dashboardRepository.addFoodList(request);
		});    //SQLIntegrityConstraintViolationException을 Spring이 자동 변환
	}

	@Test
	void testRemoveFoodListYes() {
		// given
		Food request = Food.builder().memberId(1).intakeDate("2025-06-02").build();

		// when
		int result = dashboardRepository.removeFoodList(request);

		// then
		assertEquals(1, result);
	}

	@Test
	void testRemoveFoodListNotExistMemberId() {
		// given
		Food request = Food.builder().memberId(99999).intakeDate("2025-06-02").build();

		// when
		int result = dashboardRepository.removeFoodList(request);

		// then
		assertEquals(0, result);
	}

	@Test
	void testGetFoodListYes() {

	}

	// @Test
	// void testAddFoodYes() {
	// 	// given
	// 	Food request = Food.builder().intake(200).intakeKcal(95).foodNoteId(2).foodId(8).build();
	//
	// 	// when
	// 	int result = dashboardRepository.addFood(request);
	//
	// 	// then
	// 	assertEquals(1, result);
	// }
	//
	// @Test
	// void testAddFoodNotExistFoodId() {
	// 	// given
	// 	Food request = Food.builder().intake(200).intakeKcal(95).foodNoteId(2).foodId(99999).build();
	//
	// 	// when & then
	// 	assertThrows(DataIntegrityViolationException.class, () -> {
	// 		dashboardRepository.addFood(request);
	// 	});    //SQLIntegrityConstraintViolationException을 Spring이 자동 변환
	// }
	//
	// @Test
	// void testSetIntakeYes() {
	// 	// given
	// 	Food request = Food.builder().foodInfoId(2).intake(300).build();
	//
	// 	// when
	// 	int result = dashboardRepository.setIntake(request);
	//
	// 	// then
	// 	assertEquals(1, result);
	// }
	//
	// @Test
	// void testSetIntakeNoInvalidId() {
	// 	// given
	// 	Food request = Food.builder().foodInfoId(99999).intake(300).build();
	//
	// 	// when
	// 	int result = dashboardRepository.setIntake(request);
	//
	// 	// then
	// 	assertEquals(0, result);
	// }
	//
	// @Test
	// void testRemoveFoodYes() {
	// 	// given
	// 	int foodInfoId = 30;
	//
	// 	// when
	// 	int result = dashboardRepository.removeFood(foodInfoId);
	//
	// 	// then
	// 	assertEquals(1, result);
	// }
	//
	// @Test
	// void testRemoveFoodNoInvalidId() {
	// 	// given
	// 	int foodInfoId = 99999;
	//
	// 	// when
	// 	int result = dashboardRepository.removeFood(foodInfoId);
	//
	// 	// then
	// 	assertEquals(0, result);
	// }
	//
	// @Test
	// void testGetAutoCompleteExerciseYes() {
	// 	// given
	// 	String partWord = "기";
	//
	// 	// when
	// 	List<String> result = dashboardRepository.getAutoCompleteExercise(partWord);
	//
	// 	// then
	// 	assertFalse(result.isEmpty());
	// }
	//
	// @Test
	// void testGetAutoCompleteExerciseInvalidKeyword() {
	// 	// given
	// 	String partWord = "selfit";
	//
	// 	// when
	// 	List<String> result = dashboardRepository.getAutoCompleteExercise(partWord);
	//
	// 	// then
	// 	assertTrue(result.isEmpty());
	// }

	@Test
	void testAddExerciseListYes() {
		// given
		Exercise request = Exercise.builder().memberId(1).exerciseDate("2025-06-05").build();

		// when
		int result = dashboardRepository.addExerciseList(request);

		// then
		assertEquals(1, result);
	}

	@Test
	void testAddExerciseListNotExistMemberId() {
		// given
		Exercise request = Exercise.builder().memberId(99999).exerciseDate("2025-06-05").build();

		// when & then
		assertThrows(DataIntegrityViolationException.class, () -> {
			dashboardRepository.addExerciseList(request);
		});
	}

	@Test
	void testRemoveExerciseListYes() {
		// given
		Exercise request = Exercise.builder().memberId(10).exerciseDate("2025-05-10").build();

		// when
		int result = dashboardRepository.removeExerciseList(request);

		// then
		assertEquals(1, result);
	}

	@Test
	void testRemoveExerciseListNo_NotExistMemberId() {
		// given
		Exercise request = Exercise.builder().memberId(99999).exerciseDate("2025-05-10").build();

		// when
		int result = dashboardRepository.removeExerciseList(request);

		// then
		assertEquals(0, result);
	}

	// @Test
	// void testAddExerciseYes() {
	// 	// given
	// 	Exercise request = Exercise.builder()
	// 		.exerciseMin(40)
	// 		.exerciseKcal(112)
	// 		.exerciseId(6)
	// 		.exerciseNoteId(1)
	// 		.build();
	//
	// 	// when
	// 	int result = dashboardRepository.addExercise(request);
	//
	// 	// then
	// 	assertEquals(1, result);
	// }
	//
	// @Test
	// void testAddExerciseNotExistNoteId() {
	// 	// given
	// 	Exercise request = Exercise.builder()
	// 		.exerciseMin(40)
	// 		.exerciseKcal(112)
	// 		.exerciseId(6)
	// 		.exerciseNoteId(99999)
	// 		.build();
	//
	// 	// when & then
	// 	assertThrows(DataIntegrityViolationException.class, () -> {
	// 		dashboardRepository.addExercise(request);
	// 	});
	// }
	//
	// @Test
	// void testGetExerciseDetailYes() {
	// 	// given
	// 	Exercise request = Exercise.builder().memberId(1).exerciseDate("2025-05-21").build();
	//
	// 	// when
	// 	List<Exercise> result = dashboardRepository.getExerciseDetail(request);
	//
	// 	// then
	// 	assertFalse(result.isEmpty());
	// }
	//
	// @Test
	// void testGetExerciseDetailNotExistMemberId() {
	// 	// given
	// 	Exercise request = Exercise.builder().memberId(99999).exerciseDate("2025-05-21").build();
	//
	// 	// when
	// 	List<Exercise> result = dashboardRepository.getExerciseDetail(request);
	//
	// 	// then
	// 	assertTrue(result.isEmpty());
	// }
	//
	// @Test
	// void testSetExerciseMinYes() {
	// 	// given
	// 	Exercise request = Exercise.builder().exerciseInfoId(2).exerciseMin(300).build();
	//
	// 	// when
	// 	int result = dashboardRepository.setExerciseMin(request);
	//
	// 	// then
	// 	assertEquals(1, result);
	// }
	//
	// @Test
	// void testSetExerciseMinNotExistExerciseInfoId() {
	// 	// given
	// 	Exercise request = Exercise.builder().exerciseInfoId(99999).exerciseMin(300).build();
	//
	// 	// when
	// 	int result = dashboardRepository.setExerciseMin(request);
	//
	// 	// then
	// 	assertEquals(0, result);
	// }
	//
	// //@Test
	// void testRemoveExerciseYes() {
	// 	// given
	// 	int exerciseInfoId = 1;
	//
	// 	// when
	// 	int result = dashboardRepository.removeExercise(exerciseInfoId);
	//
	// 	// then
	// 	assertEquals(1, result);
	// }
	//
	// //@Test
	// void testRemoveExerciseNotExistExerciseInfoId() {
	// 	// given
	// 	int exerciseInfoId = 99999;
	//
	// 	// when
	// 	int result = dashboardRepository.removeExercise(exerciseInfoId);
	//
	// 	// then
	// 	assertEquals(0, result);
	// }

	@Test
	void testGetCheckListYes() {
		// given
		Checklist request = Checklist.builder().memberId(1).checkDate("2025-05-01").build();

		// when
		List<Checklist> result = dashboardRepository.getCheckList(request);

		// then
		assertFalse(result.isEmpty());
	}

	@Test
	void testGetCheckListNotExistMemberId() {
		// given
		Checklist request = Checklist.builder().memberId(99999).checkDate("2025-05-01").build();

		// when
		List<Checklist> result = dashboardRepository.getCheckList(request);

		// then
		assertTrue(result.isEmpty());
	}

	// @Test
	// void testSetCheckContentYes() {
	// 	// given
	// 	Checklist request = Checklist.builder().checkId(2).checkContent("수정").build();
	//
	// 	// when
	// 	int result = dashboardRepository.setCheckContent(request);
	//
	// 	// then
	// 	assertEquals(1, result);
	// }
	//
	// @Test
	// void testSetCheckContentNotExistCheckId() {
	// 	// given
	// 	Checklist request = Checklist.builder().checkId(99999).checkContent("수정").build();
	//
	// 	// when
	// 	int result = dashboardRepository.setCheckContent(request);
	//
	// 	// then
	// 	assertEquals(0, result);
	// }
	//
	// @Test
	// void testSetIsCheckYes() {
	// 	// given
	// 	Checklist request = Checklist.builder().checkId(2).isCheck(1).build();
	//
	// 	// when
	// 	int result = dashboardRepository.setIsCheck(request);
	//
	// 	// then
	// 	assertEquals(1, result);
	// }
	//
	// @Test
	// void testSetIsCheckNotExistCheckId() {
	// 	// given
	// 	Checklist request = Checklist.builder().checkId(99999).isCheck(1).build();
	//
	// 	// when
	// 	int result = dashboardRepository.setIsCheck(request);
	//
	// 	// then
	// 	assertEquals(0, result);
	// }
	//
	// @Test
	// void testRemoveCheckItemYes() {
	// 	// given
	// 	int checkId = 2;
	//
	// 	// when
	// 	int result = dashboardRepository.removeCheckItem(checkId);
	//
	// 	// then
	// 	assertEquals(1, result);
	// }
	//
	// @Test
	// void testRemoveCheckItemNotExistCheckId() {
	// 	// given
	// 	int checkId = 99999;
	//
	// 	// when
	// 	int result = dashboardRepository.removeCheckItem(checkId);
	//
	// 	// then
	// 	assertEquals(0, result);
	// }

	@Test
	void testAddChecklistYes() {
		// given
		Checklist request = Checklist.builder().memberId(1).checkDate("2025-06-07").build();

		// when
		int result = dashboardRepository.addChecklist(request);

		// then
		assertEquals(1, result);
	}

	@Test
	void testAddChecklistNotExistMemberId() {
		// given
		Checklist request = Checklist.builder().memberId(99999).checkDate("2025-06-07").build();

		// when & then
		assertThrows(DataIntegrityViolationException.class, () -> {
			dashboardRepository.addChecklist(request);
		});
	}

	// @Test
	// void testAddCheckItemNullContent() {
	// 	// given
	// 	Checklist request = Checklist.builder()
	// 		.isCheck(0)
	// 		.checklistId(1)
	// 		.build();
	//
	// 	// when & then
	// 	assertThrows(DataIntegrityViolationException.class, () -> {
	// 		dashboardRepository.addCheckItem(request);
	// 	});
	// }
	//
	// @Test
	// void testAddCheckItemYes() {
	// 	// given
	// 	Checklist request = Checklist.builder().checkContent("물 마시기").isCheck(0).checklistId(1).build();
	//
	// 	// when
	// 	int result = dashboardRepository.addCheckItem(request);
	//
	// 	// then
	// 	assertEquals(1, result);
	// }
	//
	// @Test
	// void testAddCheckItemNotExistChecklistId() {
	// 	// given
	// 	Checklist request = Checklist.builder()
	// 		.checkContent("물 마시기")
	// 		.isCheck(0)
	// 		.checklistId(99999)
	// 		.build();
	//
	// 	// when & then
	// 	assertThrows(DataIntegrityViolationException.class, () -> {
	// 		dashboardRepository.addCheckItem(request);
	// 	});
	// }

	@Test
	void testGetGoalYes() {
		// given
		int memberId = 2;

		// when
		String result = dashboardRepository.getGoal(memberId);

		// then
		assertNotNull(result);
	}

	@Test
	void testGetGoalNotExistMemberId() {
		// given
		int memberId = 99999;

		// when
		String result = dashboardRepository.getGoal(memberId);

		// then
		assertNull(result);
	}

	// @Test
	// void testGetYearExerciseAvgInfoYes() {
	// 	// given(키 174cm, 몸무게 75kg)
	// 	Map<String, Object> param = new HashMap<>();
	// 	param.put("memberId", 1);
	// 	param.put("heightMin", 170);
	// 	param.put("heightMax", 179);
	// 	param.put("weightMin", 70);
	// 	param.put("weightMax", 79);
	// 	param.put("exerciseYear", 2025);
	//
	// 	// when
	// 	List<Map<String, Object>> result = dashboardRepository.getYearExerciseAvgInfo(param);
	//
	// 	// then
	// 	assertFalse(result.isEmpty());
	// }
	//
	// @Test
	// void testGetYearExerciseAvgInfoNotExistMemberId() {
	// 	// given(키 174cm, 몸무게 75kg)
	// 	Map<String, Object> param = new HashMap<>();
	// 	param.put("memberId", 99999);
	// 	param.put("heightMin", 170);
	// 	param.put("heightMax", 179);
	// 	param.put("weightMin", 70);
	// 	param.put("weightMax", 79);
	// 	param.put("exerciseYear", 2025);
	//
	// 	// when
	// 	List<Map<String, Object>> result = dashboardRepository.getYearExerciseAvgInfo(param);
	//
	// 	// then
	// 	assertTrue(result.isEmpty());
	// }
	//
	// @Test
	// void testGetYearExerciseAvgAgeYes() {
	// 	// given(20대)
	// 	Map<String, Object> param = new HashMap<>();
	// 	param.put("memberId", 1);
	// 	param.put("minAge", 20);
	// 	param.put("maxAge", 29);
	// 	param.put("exerciseYear", 2025);
	//
	// 	// when
	// 	List<Map<String, Object>> result = dashboardRepository.getYearExerciseAvgAge(param);
	//
	// 	// then
	// 	assertNotNull(result);
	// 	assertFalse(result.isEmpty());
	// }
	//
	// @Test
	// void testGetYearExerciseAvgAgeNotExistMemberId() {
	// 	// given(20대)
	// 	Map<String, Object> param = new HashMap<>();
	// 	param.put("memberId", 99999);
	// 	param.put("minAge", 20);
	// 	param.put("maxAge", 29);
	// 	param.put("exerciseYear", 2025);
	//
	// 	// when
	// 	List<Map<String, Object>> result = dashboardRepository.getYearExerciseAvgAge(param);
	//
	// 	// then
	// 	assertTrue(result.isEmpty());
	// }

	@Test
	void testGetYearExerciseAvgAllYes() {
		// given(20대, 키 174cm, 몸무게 75kg)
		Map<String, Object> param = new HashMap<>();
		param.put("memberId", 1);
		param.put("minAge", 20);
		param.put("maxAge", 29);
		param.put("heightMin", 170);
		param.put("heightMax", 179);
		param.put("weightMin", 70);
		param.put("weightMax", 79);
		param.put("exerciseYear", 2025);

		// when
		List<Map<String, Object>> result = dashboardRepository.getYearExerciseAvgAll(param);

		// then
		assertFalse(result.isEmpty());
	}

	@Test
	void testGetYearExerciseAvgAllNotExistMemberId() {
		// given(20대, 키 174cm, 몸무게 75kg)
		Map<String, Object> param = new HashMap<>();
		param.put("memberId", 99999);
		param.put("minAge", 20);
		param.put("maxAge", 29);
		param.put("heightMin", 170);
		param.put("heightMax", 179);
		param.put("weightMin", 70);
		param.put("weightMax", 79);
		param.put("exerciseYear", 2025);

		// when
		List<Map<String, Object>> result = dashboardRepository.getYearExerciseAvgAll(param);

		// then
		assertTrue(result.isEmpty());
	}

	// @Test
	// void testGetYearIntakeAvgInfoYes() {
	// 	// given
	// 	Map<String, Object> param = new HashMap<>();
	// 	param.put("memberId", 1);
	// 	param.put("heightMin", 170);
	// 	param.put("heightMax", 179);
	// 	param.put("weightMin", 70);
	// 	param.put("weightMax", 79);
	// 	param.put("intakeYear", 2025);
	//
	// 	// when
	// 	List<Map<String, Object>> result = dashboardRepository.getYearIntakeAvgInfo(param);
	//
	// 	// then
	// 	assertNotNull(result);
	// 	assertFalse(result.isEmpty());
	// }
	//
	// @Test
	// void testGetYearIntakeAvgInfoNotExistMemberId() {
	// 	// given
	// 	Map<String, Object> param = new HashMap<>();
	// 	param.put("memberId", 99999);
	// 	param.put("heightMin", 170);
	// 	param.put("heightMax", 179);
	// 	param.put("weightMin", 70);
	// 	param.put("weightMax", 79);
	// 	param.put("intakeYear", 2025);
	//
	// 	// when
	// 	List<Map<String, Object>> result = dashboardRepository.getYearIntakeAvgInfo(param);
	//
	// 	// then
	// 	assertTrue(result.isEmpty());
	// }
	//
	// @Test
	// void testGetYearIntakeAvgAgeYes() {
	// 	// given
	// 	Map<String, Object> param = new HashMap<>();
	// 	param.put("memberId", 1);
	// 	param.put("minAge", 20);
	// 	param.put("maxAge", 29);
	// 	param.put("intakeYear", 2025);
	//
	// 	// when
	// 	List<Map<String, Object>> result = dashboardRepository.getYearIntakeAvgAge(param);
	//
	// 	// then
	// 	assertNotNull(result);
	// 	assertFalse(result.isEmpty());
	// }
	//
	// @Test
	// void testGetYearIntakeAvgAgeNotExistMemberId() {
	// 	// given
	// 	Map<String, Object> param = new HashMap<>();
	// 	param.put("memberId", 99999);
	// 	param.put("minAge", 20);
	// 	param.put("maxAge", 29);
	// 	param.put("intakeYear", 2025);
	//
	// 	// when
	// 	List<Map<String, Object>> result = dashboardRepository.getYearIntakeAvgAge(param);
	//
	// 	// then
	// 	assertTrue(result.isEmpty());
	// }

	@Test
	void testGetYearIntakeAvgAllYes() {
		// given
		Map<String, Object> param = new HashMap<>();
		param.put("memberId", 1);
		param.put("minAge", 20);
		param.put("maxAge", 29);
		param.put("heightMin", 170);
		param.put("heightMax", 179);
		param.put("weightMin", 70);
		param.put("weightMax", 79);
		param.put("intakeYear", 2025);

		// when
		List<Map<String, Object>> result = dashboardRepository.getYearIntakeAvgAll(param);

		// then
		assertNotNull(result);
		assertFalse(result.isEmpty());
	}

	@Test
	void testGetYearIntakeAvgAllNotExistMemberId() {
		// given
		Map<String, Object> param = new HashMap<>();
		param.put("memberId", 99999);
		param.put("minAge", 20);
		param.put("maxAge", 29);
		param.put("heightMin", 170);
		param.put("heightMax", 179);
		param.put("weightMin", 70);
		param.put("weightMax", 79);
		param.put("intakeYear", 2025);

		// when
		List<Map<String, Object>> result = dashboardRepository.getYearIntakeAvgAll(param);

		// then
		assertTrue(result.isEmpty());

	}

	@Test
	void testIsChecklistYes() {
		// given
		int memberId = 2;
		String checkDate = "2025-05-02";

		// when
		int result = dashboardRepository.isChecklist(memberId, checkDate);

		// then
		assertEquals(1, result);
	}

	@Test
	void testIsChecklistNotExistMemberId() {
		// given
		int memberId = 99999;
		String checkDate = "2025-05-02";

		// when
		int result = dashboardRepository.isChecklist(memberId, checkDate);

		// then
		assertEquals(0, result);
	}

	@Test
	void testIsChecklistNotExistDate() {
		// given
		int memberId = 2;
		String checkDate = "9999-05-02";

		// when
		int result = dashboardRepository.isChecklist(memberId, checkDate);

		// then
		assertEquals(0, result);
	}

	@Test
	void testIsFoodNoteYes() {
		// given
		int memberId = 2;
		String intakeDate = "2025-05-02";

		// when
		int result = dashboardRepository.isFoodNote(memberId, intakeDate);

		// then
		assertEquals(1, result);
	}

	@Test
	void testIsFoodNoteNotExistMemberId() {
		// given
		int memberId = 99999;
		String intakeDate = "2025-05-02";

		// when
		int result = dashboardRepository.isFoodNote(memberId, intakeDate);

		// then
		assertEquals(0, result);
	}

	@Test
	void testIsFoodNoteNotExistDate() {
		// given
		int memberId = 2;
		String intakeDate = "9999-05-02";

		// when
		int result = dashboardRepository.isFoodNote(memberId, intakeDate);

		// then
		assertEquals(0, result);
	}

	@Test
	void testIsExerciseNoteYes() {
		// given
		int memberId = 2;
		String exerciseDate = "2025-05-02";

		// when
		int result = dashboardRepository.isExerciseNote(memberId, exerciseDate);

		// then
		assertEquals(1, result);
	}

	@Test
	void testIsExerciseNoteNotExistMemberId() {
		// given
		int memberId = 99999;
		String exerciseDate = "2025-05-02";

		// when
		int result = dashboardRepository.isExerciseNote(memberId, exerciseDate);

		// then
		assertEquals(0, result);
	}

	@Test
	void testIsExerciseNoteNotExistDate() {
		// given
		int memberId = 2;
		String exerciseDate = "9999-05-02";

		// when
		int result = dashboardRepository.isExerciseNote(memberId, exerciseDate);

		// then
		assertEquals(0, result);
	}

	// @Test
	// void testGetUnitKcal() {
	// 	// given
	// 	int foodId = 1;
	// 	// when
	// 	int result = dashboardRepository.getUnitKcal(foodId);
	// 	// then
	// 	assertEquals(95, result);
	// }
	//
	// @Test
	// void testGetMet() {
	// 	// given
	// 	int exerciseId = 1;
	// 	//when
	// 	int result = dashboardRepository.getMet(exerciseId);
	// 	//then
	// 	assertEquals(6, result);
	// }

	// @Test
	// void testGetWeight() {
	// 	// given
	// 	int exerciseNoteId = 1;
	// 	// when
	// 	int result = dashboardRepository.getWeight(exerciseNoteId);
	// 	//then
	// 	assertEquals(70, result);
	// }
}

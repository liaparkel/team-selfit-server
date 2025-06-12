package com.oopsw.selfit.service;

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

@Transactional
@SpringBootTest
public class DashboardServiceTests {
	@Autowired
	DashboardService dashboardService;
	// @Autowired
	// private DashboardRepository dashboardRepository;
	// @Autowired
	// private CheckRepository checkRepository;

	// @Test
	// void testGetFoodWeightYes() {
	// 	// given
	// 	String foodName = "우유";
	// 	// when
	// 	HashMap map = dashboardService.getFoodWeight(foodName);
	// 	// then
	// 	assertEquals("ml", map.get("unitPart"));
	// 	assertEquals(200, map.get("numberPart"));
	// }
	//
	// @Test
	// void testGetFoodWeightNameNotExist() {
	// 	// given
	// 	String foodName = "볼펜";
	//
	// 	// when & then
	// 	assertThrows(NullPointerException.class, () -> {
	// 		Map<String, Object> map = dashboardService.getFoodWeight(foodName);
	// 	});
	// }

	@Test
	void testGetBmrYes() {
		// given
		int memberId = 2;
		// when
		int bmr = dashboardService.getBmr(memberId);
		// then
		assertEquals(1300, bmr);
	}

	@Test
	void testGetBmrNotExistMemberId() {
		// given
		int memberId = 99999;

		// when & then
		assertThrows(NullPointerException.class, () -> {
			dashboardService.getBmr(memberId);
		});
	}

	@Test
	void testGetIntakeKcalYes() {
		// given
		Food f = Food.builder().memberId(1).intakeDate("2025-05-21").build();
		// when
		Food newf = dashboardService.getIntakeKcal(f);
		// then
		assertNotNull(newf);
		assertTrue(newf.getIntakeSum() > 0);
	}

	@Test
	void testGetIntakeKcalNotExistMemberId() {
		// given
		Food request = Food.builder().memberId(99999).intakeDate("2025-05-21").build();
		// when
		Food result = dashboardService.getIntakeKcal(request);
		// than
		assertNull(result);
	}

	@Test
	void testGetExerciseKcalYes() {
		// given
		Exercise e = Exercise.builder().memberId(1).exerciseDate("2025-05-21").build();
		// when
		Exercise newe = dashboardService.getExerciseKcal(e);
		// then
		assertNotNull(newe);
		assertTrue(newe.getExerciseSum() > 0);
	}

	@Test
	void testGetExerciseKcalNotExistMemberId() {
		// given
		Exercise request = Exercise.builder().memberId(99999).exerciseDate("2025-05-21").build();

		// when
		Exercise result = dashboardService.getExerciseKcal(request);

		// than
		assertNull(result);
	}

	@Test
	void testGetYearIntakeKcalYes() {
		// given
		HashMap<String, Object> map = new HashMap<>();
		map.put("memberId", 1);
		map.put("intakeYear", 2025);
		// when
		List<Food> result = dashboardService.getYearIntakeKcal(map);
		// then
		assertNotNull(result);
		assertFalse(result.isEmpty());
	}

	@Test
	void testGetYearIntakeKcalNotExistMemberId() {
		// given
		HashMap<String, Object> map = new HashMap<>();
		map.put("memberId", 99999);
		map.put("intakeYear", 2025);
		// when
		List<Food> result = dashboardService.getYearIntakeKcal(map);
		// then
		assertTrue(result.isEmpty());
	}

	@Test
	void testGetYearExerciseKcalYes() {
		// given
		HashMap<String, Object> map = new HashMap<>();
		map.put("memberId", 1);
		map.put("exerciseYear", 2025);

		// when
		List<Exercise> result = dashboardService.getYearExerciseKcal(map);

		// then
		assertNotNull(result);
		assertFalse(result.isEmpty());
	}

	@Test
	void testGetYearExerciseKcalNotExistMemberId() {
		// given
		HashMap<String, Object> map = new HashMap<>();
		map.put("memberId", 99999);
		map.put("exerciseYear", 2025);

		// when
		List<Exercise> result = dashboardService.getYearExerciseKcal(map);

		// then
		assertTrue(result.isEmpty());
	}

	// @Test
	// void testGetIntakeDetailYes() {
	// 	// given
	// 	Food f = Food.builder().memberId(1).intakeDate("2025-05-01").build();
	// 	// when
	// 	List list = dashboardService.getIntakeDetail(f);
	// 	// then
	// 	assertEquals(4, list.size());
	// }
	//
	// @Test
	// void testGetIntakeDetailNotExistMemberId() {
	// 	// given
	// 	Food request = Food.builder().memberId(99999).intakeDate("2025-05-21").build();
	// 	// when
	// 	List<Food> result = dashboardService.getIntakeDetail(request);
	// 	// then
	// 	assertTrue(result.isEmpty());
	// }
	//
	// @Test
	// void testGetAutoCompleteFoodYes() {
	// 	// given
	// 	String partWord = "유";
	// 	// when
	// 	List<String> result = dashboardService.getAutoCompleteFood(partWord);
	// 	// then
	// 	assertFalse(result.isEmpty());
	// }
	//
	// @Test
	// void testGetAutoCompleteFoodInvalidKeyword() {
	// 	// given
	// 	String partWord = "selfit";
	// 	// when
	// 	List<String> result = dashboardService.getAutoCompleteFood(partWord);
	// 	// then
	// 	assertTrue(result.isEmpty());
	// }

	@Test
	void testAddFoodListYes() {
		// given
		Food request = Food.builder()
			.memberId(1)
			.intakeDate("2025-06-05")
			.build();

		// when
		int foodNoteId = dashboardService.addFoodList(request);

		// then
		assertTrue(foodNoteId > 0);
	}

	@Test
	void testAddFoodListNotExistMemberId() {
		// given
		Food request = Food.builder().memberId(99999).intakeDate("2025-05-05").build();

		// when & then
		assertThrows(DataIntegrityViolationException.class, () -> {
			dashboardService.addFoodList(request);
		});    //SQLIntegrityConstraintViolationException을 Spring이 자동 변환
	}

	@Test
	void testAddFoodListDuplicateDate() {
		// given
		Food request = Food.builder().memberId(1).intakeDate("2025-05-01").build();

		// when & then
		assertThrows(IllegalStateException.class, () -> {
			dashboardService.addFoodList(request);
		});    //SQLIntegrityConstraintViolationException을 Spring이 자동 변환
	}

	@Test
	void testRemoveFoodListYes() {
		// given
		Food request = Food.builder().memberId(1).intakeDate("2025-05-01").build();
		// when
		boolean result = dashboardService.removeFoodList(request);
		// then
		assertTrue(result);
	}

	@Test
	void testRemoveFoodListNotExistMemberId() {
		// given
		Food request = Food.builder().memberId(99999).intakeDate("2025-05-01").build();

		// when
		boolean result = dashboardService.removeFoodList(request);

		// then
		assertFalse(result);
	}

	@Test
	void testRemoveFoodListWrongDate() {
		// given
		Food request = Food.builder().memberId(1).intakeDate("2025-06-31").build();
		// when
		boolean result = dashboardService.removeFoodList(request);
		// then
		assertFalse(result);
	}

	// @Test
	// void testAddFoodYes() {
	// 	// given
	// 	Food request = Food.builder().intake(200).foodNoteId(2).foodId(8).build();
	// 	// when
	// 	boolean result = dashboardService.addFood(request);
	// 	// then
	// 	assertTrue(result);
	// }
	//
	// @Test
	// void testAddFoodZero() {
	// 	// given
	// 	Food request = Food.builder().intake(-200).foodNoteId(2).foodId(8).build();
	// 	// when & then
	// 	assertThrows(IllegalArgumentException.class, () -> {
	// 		dashboardService.addFood(request);
	// 	});
	// }
	//
	// @Test
	// void testAddFoodNotExistFoodId() {
	// 	// given
	// 	Food request = Food.builder().intake(200).intakeKcal(95).foodNoteId(2).foodId(99999).build();
	//
	// 	// when & then
	// 	assertThrows(BindingException.class, () -> {
	// 		dashboardService.addFood(request);
	// 	});    //SQLIntegrityConstraintViolationException을 Spring이 자동 변환
	// }
	//
	// @Test
	// void testSetIntakeYes() {
	// 	// given
	// 	Food request = Food.builder().foodInfoId(2).intake(300).build();
	// 	// when
	// 	boolean result = dashboardService.setIntake(request);
	// 	// then
	// 	assertTrue(result);
	// }
	//
	// @Test
	// void testSetIntakeNoInvalidId() {
	// 	// given
	// 	Food request = Food.builder().foodInfoId(99999).intake(300).build();
	//
	// 	// when
	// 	boolean result = dashboardService.setIntake(request);
	//
	// 	// then
	// 	assertFalse(result);
	// }
	//
	// @Test
	// void testRemoveFoodYes() {
	// 	// given
	// 	int foodInfoId = 30;
	// 	// when
	// 	boolean result = dashboardService.removeFood(foodInfoId);
	// 	// then
	// 	assertTrue(result);
	// }
	//
	// @Test
	// void testRemoveFoodNoInvalidId() {
	// 	// given
	// 	int foodInfoId = 99999;
	//
	// 	// when
	// 	boolean result = dashboardService.removeFood(foodInfoId);
	//
	// 	// then
	// 	assertFalse(result);
	// }
	//
	// @Test
	// void testGetAutoCompleteExerciseYes() {
	// 	// given
	// 	String partWord = "기";
	// 	// when
	// 	List<String> result = dashboardService.getAutoCompleteExercise(partWord);
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
	// 	List<String> result = dashboardService.getAutoCompleteExercise(partWord);
	//
	// 	// then
	// 	assertTrue(result.isEmpty());
	// }

	@Test
	void testAddExerciseListYes() {
		// given
		Exercise request = Exercise.builder().memberId(1).exerciseDate("2025-04-01").build();

		// when
		int exerciseNoteId = dashboardService.addExerciseList(request);

		// then
		assertTrue(exerciseNoteId > 0);
	}

	@Test
	void testAddExerciseListNotExistMemberId() {
		// given
		Exercise request = Exercise.builder().memberId(99999).exerciseDate("2025-06-05").build();

		// when & then
		assertThrows(DataIntegrityViolationException.class, () -> {
			dashboardService.addExerciseList(request);
		});
	}

	@Test
	void testAddExerciseListDuplicateDate() {
		// given
		Exercise request = Exercise.builder().memberId(1).exerciseDate("2025-05-01").build();

		// when & then
		assertThrows(IllegalStateException.class, () -> {
			dashboardService.addExerciseList(request);
		});    //SQLIntegrityConstraintViolationException을 Spring이 자동 변환
	}

	@Test
	void testRemoveExerciseListYes() {
		// given
		Exercise request = Exercise.builder().memberId(1).exerciseDate("2025-05-01").build();
		// when
		boolean result = dashboardService.removeExerciseList(request);
		// then
		assertTrue(result);
	}

	@Test
	void testRemoveExerciseListNo_NotExistMemberId() {
		// given
		Exercise request = Exercise.builder().memberId(99999).exerciseDate("2025-05-10").build();

		// when
		boolean result = dashboardService.removeExerciseList(request);

		// then
		assertFalse(result);
	}

	// @Test
	// void testAddExerciseYes() {
	// 	// given
	// 	Exercise request = Exercise.builder()
	// 		.exerciseMin(160)
	// 		.exerciseId(7)
	// 		.exerciseNoteId(1)
	// 		.build();
	// 	// when
	// 	boolean result = dashboardService.addExercise(request);
	// 	// then
	// 	assertTrue(result);
	// }
	//
	// @Test
	// void testAddExerciseZero() {
	// 	// given
	// 	Exercise request = Exercise.builder()
	// 		.exerciseMin(-20)
	// 		.exerciseId(6)
	// 		.exerciseNoteId(1)
	// 		.build();
	// 	// when & then
	// 	assertThrows(IllegalArgumentException.class, () -> {
	// 		boolean result = dashboardService.addExercise(request);
	// 	});
	// }
	//
	// @Test
	// void testAddExerciseNotExistNoteId() {
	// 	// given
	// 	Exercise request = Exercise.builder()
	// 		.exerciseMin(40)
	// 		.exerciseId(6)
	// 		.exerciseNoteId(99999)
	// 		.build();
	//
	// 	// when & then
	// 	assertThrows(BindingException.class, () -> {
	// 		dashboardService.addExercise(request);
	// 	});
	// }
	//
	// @Test
	// void testGetExerciseDetailYes() {
	// 	// given
	// 	Exercise request = Exercise.builder().memberId(1).exerciseDate("2025-05-21").build();
	// 	// when
	// 	List<Exercise> result = dashboardService.getExerciseDetail(request);
	// 	// then
	// 	System.out.println(result);
	// 	assertFalse(result.isEmpty());
	// }
	//
	// @Test
	// void testGetExerciseDetailNotExistMemberId() {
	// 	// given
	// 	Exercise request = Exercise.builder().memberId(99999).exerciseDate("2025-05-21").build();
	//
	// 	// when
	// 	List<Exercise> result = dashboardService.getExerciseDetail(request);
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
	// 	boolean result = dashboardService.setExerciseMin(request);
	//
	// 	// then
	// 	assertTrue(result);
	// }
	//
	// @Test
	// void testSetExerciseMinNotExistExerciseInfoId() {
	// 	// given
	// 	Exercise request = Exercise.builder().exerciseInfoId(99999).exerciseMin(300).build();
	//
	// 	// when
	// 	boolean result = dashboardService.setExerciseMin(request);
	//
	// 	// then
	// 	assertFalse(result);
	// }
	//
	// @Test
	// void testSetExerciseMinZero() {
	// 	// given
	// 	Exercise request = Exercise.builder().exerciseInfoId(2).exerciseMin(0).build();
	//
	// 	// when & then
	// 	assertThrows(IllegalArgumentException.class, () -> {
	// 		dashboardService.setExerciseMin(request);
	// 	});
	// }
	//
	// //@Test
	// void testRemoveExerciseYes() {
	// 	// given
	// 	int exerciseInfoId = 1;
	//
	// 	// when
	// 	boolean result = dashboardService.removeExercise(exerciseInfoId);
	//
	// 	// then
	// 	assertTrue(result);
	// }
	//
	// //@Test
	// void testRemoveExerciseNotExistExerciseInfoId() {
	// 	// given
	// 	int exerciseInfoId = 99999;
	//
	// 	// when
	// 	boolean result = dashboardService.removeExercise(exerciseInfoId);
	//
	// 	// then
	// 	assertFalse(result);
	// }

	@Test
	void testGetCheckListYes() {
		// given
		Checklist request = Checklist.builder().memberId(1).checkDate("2025-05-01").build();

		// when
		List<Checklist> result = dashboardService.getCheckList(request);

		// then
		assertFalse(result.isEmpty());
	}

	@Test
	void testGetCheckListNotExistMemberId() {
		// given
		Checklist request = Checklist.builder().memberId(99999).checkDate("2025-05-01").build();

		// when
		List<Checklist> result = dashboardService.getCheckList(request);

		// then
		assertTrue(result.isEmpty());
	}

	@Test
	void testGetCheckListNotExistCheckDate() {
		// given
		Checklist request = Checklist.builder().memberId(99999).checkDate("9999-05-01").build();

		// when
		List<Checklist> result = dashboardService.getCheckList(request);

		// then
		assertTrue(result.isEmpty());
	}

	// @Test
	// void testSetCheckContentYes() {
	// 	// given
	// 	Checklist request = Checklist.builder().checkId(2).checkContent("수정").build();
	//
	// 	// when
	// 	boolean result = dashboardService.setCheckContent(request);
	//
	// 	// then
	// 	assertTrue(result);
	// }
	//
	// @Test
	// void testSetCheckContentNotExistCheckId() {
	// 	// given
	// 	Checklist request = Checklist.builder().checkId(99999).checkContent("수정").build();
	//
	// 	// when
	// 	boolean result = dashboardService.setCheckContent(request);
	//
	// 	// then
	// 	assertFalse(result);
	// }
	// @Test
	// public void testSetCheckItemYes() {
	// 	// given
	// 	CheckItem saved = checkRepository.save(
	// 		CheckItem.builder()
	// 			.checkContent("수정 전")
	// 			.isCheck(false)
	// 			.checklistId(1L)
	// 			.build()
	// 	);
	//
	// 	Checklist dto = Checklist.builder()
	// 		.checkId(saved.getCheckId().intValue())
	// 		.checkContent("수정 후")
	// 		.build();
	//
	// 	// when
	// 	boolean result = dashboardService.setCheckItem(dto);
	//
	// 	// then
	// 	assertTrue(result);
	// 	Optional<CheckItem> updated = checkRepository.findById(saved.getCheckId());
	// 	assertEquals("수정 후", updated.get().getCheckContent());
	// }
	//
	// @Test
	// public void testSetCheckItemInvalid() {
	// 	// given
	// 	Checklist dto = Checklist.builder()
	// 		.checkId(99999)
	// 		.checkContent("수정 실패")
	// 		.build();
	//
	// 	// when + then
	// 	assertThrows(IllegalArgumentException.class, () -> dashboardService.setCheckItem(dto));
	// }

	// @Test
	// void testSetIsCheckYes() {
	// 	// given
	// 	Checklist request = Checklist.builder().checkId(2).isCheck(1).build();
	//
	// 	// when
	// 	boolean result = dashboardService.setIsCheck(request);
	//
	// 	// then
	// 	assertTrue(result);
	// }
	//
	// @Test
	// void testSetIsCheckNotExistCheckId() {
	// 	// given
	// 	Checklist request = Checklist.builder().checkId(99999).isCheck(1).build();
	//
	// 	// when
	// 	boolean result = dashboardService.setIsCheck(request);
	//
	// 	// then
	// 	assertFalse(result);
	// }
	// @Test
	// public void testSetIsCheckItemYes() {
	// 	// given
	// 	CheckItem savedItem = checkRepository.save(
	// 		CheckItem.builder()
	// 			.checkContent("토글 테스트")
	// 			.isCheck(false)
	// 			.checklistId(1L)
	// 			.build()
	// 	);
	//
	// 	Checklist dto = Checklist.builder()
	// 		.checkId(savedItem.getCheckId().intValue())  // Long → int 형변환
	// 		.build();
	//
	// 	// when
	// 	boolean result = dashboardService.setIsCheckItem(dto);
	//
	// 	// then
	// 	assertTrue(result);
	// 	Optional<CheckItem> updated = checkRepository.findById(savedItem.getCheckId());
	// 	assertEquals(true, updated.get().getIsCheck());
	// }
	//
	// @Test
	// public void testSetIsCheckItemInvalid() {
	// 	// given
	// 	Checklist dto = Checklist.builder()
	// 		.checkId(99999)
	// 		.build();
	//
	// 	// when + then
	// 	assertThrows(IllegalArgumentException.class, () -> dashboardService.setIsCheckItem(dto));
	// }

	// @Test
	// void testRemoveCheckItemYes() {
	// 	// given
	// 	int checkId = 2;
	//
	// 	// when
	// 	boolean result = dashboardService.removeCheckItem(checkId);
	//
	// 	// then
	// 	assertTrue(result);
	// }
	//
	// @Test
	// void testRemoveCheckItemNotExistCheckId() {
	// 	// given
	// 	int checkId = 99999;
	//
	// 	// when
	// 	boolean result = dashboardService.removeCheckItem(checkId);
	//
	// 	// then
	// 	assertFalse(result);
	// }
	// @Test
	// public void testRemoveCheckItemYes() {
	// 	// given
	// 	CheckItem checkItem = checkRepository.save(
	// 		CheckItem.builder()
	// 			.checkContent("삭제 테스트")
	// 			.isCheck(false)
	// 			.checklistId(1L)
	// 			.build()
	// 	);
	//
	// 	Checklist dto = Checklist.builder()
	// 		.checkId(checkItem.getCheckId().intValue())
	// 		.build();
	//
	// 	// when + then
	// 	assertDoesNotThrow(() -> dashboardService.removeCheckItem(dto));
	// }
	//
	// @Test
	// public void testRemoveCheckItemInvalid() {
	// 	// given: 존재하지 않는 checkId 사용
	// 	Checklist dto = Checklist.builder()
	// 		.checkId(99999)  // 없는 ID
	// 		.build();
	//
	// 	// when + then
	// 	assertThrows(IllegalArgumentException.class, () -> dashboardService.removeCheckItem(dto));
	// }

	@Test
	void testAddChecklistYes() {
		// given
		Checklist request = Checklist.builder().memberId(1).checkDate("2025-04-01").build();

		// when
		int checklistId = dashboardService.addChecklist(request);

		// then
		assertTrue(checklistId > 0);
	}

	@Test
	void testAddChecklistNotExistMemberId() {
		// given
		Checklist request = Checklist.builder().memberId(99999).checkDate("2025-06-07").build();

		// when & then
		assertThrows(DataIntegrityViolationException.class, () -> {
			dashboardService.addChecklist(request);
		});
	}

	@Test
	void testAddChecklistDuplicateDate() {
		// given
		Checklist request = Checklist.builder().memberId(2).checkDate("2025-05-02").build();

		// when & then
		assertThrows(IllegalStateException.class, () -> {
			dashboardService.addChecklist(request);
		});
	}

	// @Test
	// void testAddCheckItemYes() {
	// 	// given
	// 	Checklist request = Checklist.builder().checkContent("물 마시기").isCheck(0).checklistId(1).build();
	//
	// 	// when
	// 	boolean result = dashboardService.addCheckItem(request);
	//
	// 	// then
	// 	assertTrue(result);
	// }
	//
	// @Test
	// void testAddCheckItemNotExistChecklistId() {
	// 	// given
	// 	Checklist request = Checklist.builder().checkContent("물 마시기").isCheck(0).checklistId(99999).build();
	//
	// 	// when & then
	// 	assertThrows(DataIntegrityViolationException.class, () -> {
	// 		dashboardService.addCheckItem(request);
	// 	});
	// }
	// @Test
	// public void testAddCheckItemYes() {
	// 	// given: 데이터 준비
	// 	Checklist dto = Checklist.builder()
	// 		.checklistId(1)
	// 		.checkContent("물 마시기")
	// 		.build();
	//
	// 	// when + then
	// 	assertDoesNotThrow(() -> dashboardService.addCheckItem(dto));
	// }

	// @Test
	// public void testAddCheckItemOverLimit() {
	// 	int checklistId = 1;
	//
	// 	// given: 체크리스트에 이미 10개가 있다고 가정
	// 	for (int i = 0; i < 5; i++) {
	// 		Checklist dto = Checklist.builder()
	// 			.checklistId(checklistId)
	// 			.checkContent("기존 항목 " + i)
	// 			.build();
	//
	// 		dashboardService.addCheckItem(dto);
	// 	}
	//
	// 	// 6번째 넣으면 예외 발생해야 함
	// 	Checklist overLimitDto = Checklist.builder()
	// 		.checklistId(checklistId)
	// 		.checkContent("초과 항목")
	// 		.build();
	//
	// 	// when + then
	// 	assertThrows(IllegalStateException.class, () -> dashboardService.addCheckItem(overLimitDto));
	// }

	@Test
	void testGetGoalYes() {
		// given
		int memberId = 1;

		// when
		String result = dashboardService.getGoal(memberId);

		// then
		assertEquals("유지", result);
	}

	@Test
	void testGetGoalNotExistMemberId() {
		// given
		int memberId = 99999;

		// when + then
		assertThrows(IllegalArgumentException.class, () -> {
			dashboardService.getGoal(memberId);
		});
	}

	@Test
	void testGetGoalNotEqualGoal() {
		// given
		int memberId = 1;

		// when
		String result = dashboardService.getGoal(memberId);

		// then
		assertNotEquals("감량", result);
	}

	// @Test
	// void testGetYearExerciseAvgInfoYes() {
	// 	// given
	// 	int memberId = 1;
	// 	int exerciseYear = 2025;
	//
	// 	// when
	// 	List<Map<String, Object>> result = dashboardService.getYearExerciseAvgInfo(memberId, exerciseYear);
	//
	// 	// then
	// 	assertNotNull(result);
	// 	assertFalse(result.isEmpty());
	// }
	//
	// @Test
	// void testGetYearExerciseAvgInfoNoDataForYear() {
	// 	// given
	// 	int memberId = 1;
	// 	int exerciseYear = 9999;
	//
	// 	// when
	// 	List<Map<String, Object>> result = dashboardService.getYearExerciseAvgInfo(memberId, exerciseYear);
	//
	// 	// then
	// 	assertNotNull(result);
	// 	assertTrue(result.isEmpty());
	// }
	//
	// @Test
	// void testGetYearExerciseAvgInfoNotExistMemberId() {
	// 	// given
	// 	int memberId = 9999;
	// 	int exerciseYear = 2025;
	//
	// 	// when & then
	// 	assertThrows(NullPointerException.class, () -> {
	// 		dashboardService.getYearExerciseAvgInfo(memberId, exerciseYear);
	// 	});
	// }
	//
	// @Test
	// void testGetYearExerciseAvgAgeYes() {
	// 	// given
	// 	int memberId = 1;
	// 	int exerciseYear = 2025;
	//
	// 	// when
	// 	List<Map<String, Object>> result = dashboardService.getYearExerciseAvgAge(memberId, exerciseYear);
	//
	// 	// then
	// 	assertNotNull(result);
	// 	assertFalse(result.isEmpty());
	// }
	//
	// @Test
	// void testGetYearExerciseAvgAgeNoDataForYear() {
	// 	// given
	// 	int memberId = 1;
	// 	int exerciseYear = 9999;
	//
	// 	// when
	// 	List<Map<String, Object>> result = dashboardService.getYearExerciseAvgAge(memberId, exerciseYear);
	//
	// 	// then
	// 	assertNotNull(result);
	// 	assertTrue(result.isEmpty());
	// }
	//
	// @Test
	// void testGetYearExerciseAvgAgeNotExistMemberId() {
	// 	// given
	// 	int memberId = 9999;
	// 	int exerciseYear = 2025;
	//
	// 	// when & then
	// 	assertThrows(NullPointerException.class, () -> {
	// 		dashboardService.getYearExerciseAvgAge(memberId, exerciseYear);
	// 	});
	// }

	@Test
	void testGetYearExerciseAvgAllYes() {
		// given
		int memberId = 1;
		int exerciseYear = 2025;

		// when
		List<Map<String, Object>> result = dashboardService.getYearExerciseAvgAll(memberId, exerciseYear);

		// then
		assertNotNull(result);
		assertFalse(result.isEmpty());
	}

	@Test
	void testGetYearExerciseAvgAllNoDataForYear() {
		// given
		int memberId = 1;
		int exerciseYear = 9999;

		// when
		List<Map<String, Object>> result = dashboardService.getYearExerciseAvgAll(memberId, exerciseYear);

		// then
		assertNotNull(result);
		assertTrue(result.isEmpty());
	}

	@Test
	void testGetYearExerciseAvgAllNotExistMemberId() {
		// given
		int memberId = 9999;
		int exerciseYear = 2025;

		// when & then
		assertThrows(NullPointerException.class, () -> {
			dashboardService.getYearExerciseAvgAll(memberId, exerciseYear);
		});
	}

	// @Test
	// void testGetYearIntakeAvgInfoYes() {
	// 	// given
	// 	int memberId = 1;
	// 	int intakeYear = 2025;
	//
	// 	// when
	// 	List<Map<String, Object>> result = dashboardService.getYearIntakeAvgInfo(memberId, intakeYear);
	//
	// 	// then
	// 	assertNotNull(result);
	// 	assertFalse(result.isEmpty());
	// }
	//
	// @Test
	// void testGetYearIntakeAvgInfoNoDataForYear() {
	// 	// given
	// 	int memberId = 1;
	// 	int intakeYear = 9999;
	//
	// 	// when
	// 	List<Map<String, Object>> result = dashboardService.getYearIntakeAvgInfo(memberId, intakeYear);
	//
	// 	// then
	// 	assertNotNull(result);
	// 	assertTrue(result.isEmpty());
	// }
	//
	// @Test
	// void testGetYearIntakeAvgInfoNotExistMemberId() {
	// 	// given
	// 	int memberId = 9999;
	// 	int intakeYear = 2025;
	//
	// 	// when & then
	// 	assertThrows(NullPointerException.class, () -> {
	// 		dashboardService.getYearIntakeAvgInfo(memberId, intakeYear);
	// 	});
	// }
	//
	// @Test
	// void testGetYearIntakeAvgAgeYes() {
	// 	// given
	// 	int memberId = 1;
	// 	int intakeYear = 2025;
	//
	// 	// when
	// 	List<Map<String, Object>> result = dashboardService.getYearIntakeAvgAge(memberId, intakeYear);
	//
	// 	// then
	// 	assertNotNull(result);
	// 	assertFalse(result.isEmpty());
	// }
	//
	// @Test
	// void testGetYearIntakeAvgAgeNoDataForYear() {
	// 	// given
	// 	int memberId = 1;
	// 	int intakeYear = 9999;
	//
	// 	// when
	// 	List<Map<String, Object>> result = dashboardService.getYearIntakeAvgAge(memberId, intakeYear);
	//
	// 	// then
	// 	assertNotNull(result);
	// 	assertTrue(result.isEmpty());
	// }
	//
	// @Test
	// void testGetYearIntakeAvgAgeNotExistMemberId() {
	// 	// given
	// 	int memberId = 9999;
	// 	int intakeYear = 2025;
	//
	// 	// when & then
	// 	assertThrows(NullPointerException.class, () -> {
	// 		dashboardService.getYearIntakeAvgAge(memberId, intakeYear);
	// 	});
	// }

	@Test
	void testGetYearIntakeAvgAllYes() {
		// given
		int memberId = 1;
		int intakeYear = 2025;

		// when
		List<Map<String, Object>> result = dashboardService.getYearIntakeAvgAll(memberId, intakeYear);

		// then
		assertNotNull(result);
		assertFalse(result.isEmpty());
	}

	@Test
	void testGetYearIntakeAvgAllNoDataForYear() {
		// given
		int memberId = 1;
		int intakeYear = 9999;

		// when
		List<Map<String, Object>> result = dashboardService.getYearIntakeAvgAll(memberId, intakeYear);

		// then
		assertNotNull(result);
		assertTrue(result.isEmpty());
	}

	@Test
	void testGetYearIntakeAvgAllNotExistMemberId() {
		// given
		int memberId = 9999;
		int intakeYear = 2025;

		// when & then
		assertThrows(NullPointerException.class, () -> {
			dashboardService.getYearIntakeAvgAll(memberId, intakeYear);
		});
	}

}

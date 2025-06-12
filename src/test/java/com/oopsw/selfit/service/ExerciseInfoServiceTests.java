package com.oopsw.selfit.service;

import static org.junit.jupiter.api.Assertions.*;

import java.util.List;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import com.oopsw.selfit.domain.ExerciseInfos;
import com.oopsw.selfit.dto.Exercise;
import com.oopsw.selfit.repository.DashboardRepository;
import com.oopsw.selfit.repository.ExerciseInfoRepository;

@SpringBootTest
public class ExerciseInfoServiceTests {

	@Autowired
	private ExerciseInfoService exerciseInfoService;
	@Autowired
	private DashboardRepository dashboardRepository;
	@Autowired
	private ExerciseInfoRepository exerciseInfoRepository;

	@Test
	void testRemoveExerciseYes() {
		// given
		ExerciseInfos exercise = ExerciseInfos.builder()
			.exerciseName("등산")
			.exerciseNoteId(1)
			.exerciseMin(30)
			.met(3.0f)
			.build();

		ExerciseInfos saved = exerciseInfoRepository.save(exercise);
		int id = saved.getExerciseInfoId();

		// when
		boolean result = exerciseInfoService.removeExercise(id);

		// then
		assertTrue(result);
		assertFalse(exerciseInfoRepository.existsById(id));
	}

	@Test
	public void testAddExerciseInfoYes() {
		// given
		int exerciseNoteId = 1;
		int exerciseMin = 30;
		float met = 6.0f;

		// 예상 weight → getWeight() 가 반환한다고 가정
		float weight = dashboardRepository.getWeight(exerciseNoteId);
		float expectedKcal = weight * met * exerciseMin / 60f;

		Exercise dto = Exercise.builder()
			.exerciseNoteId(exerciseNoteId)
			.exerciseMin(exerciseMin)
			.met(met)
			.exerciseName("등산")
			.build();

		// when
		boolean result = exerciseInfoService.addExerciseInfo(dto);

		// then
		assertTrue(result);

		// 저장된 데이터 확인 (가장 최근 것 기준)
		ExerciseInfos saved = exerciseInfoRepository.findByExerciseNoteId(exerciseNoteId)
			.stream()
			.sorted((a, b) -> b.getExerciseInfoId() - a.getExerciseInfoId()) // 최신순
			.findFirst()
			.orElseThrow(() -> new AssertionError("운동 정보 저장 실패"));

		assertEquals(exerciseMin, saved.getExerciseMin());
		assertEquals(expectedKcal, saved.getExerciseKcal(), 0.01f); // 소수 오차 허용
	}

	@Test
	public void testSetExerciseMinYes() {
		// given
		ExerciseInfos exercise = ExerciseInfos.builder()
			.exerciseNoteId(1)
			.exerciseMin(30)
			.met(3.0f)
			.exerciseKcal(150f)
			.exerciseName("테스트운동")
			.build();

		ExerciseInfos saved = exerciseInfoRepository.save(exercise);
		int id = saved.getExerciseInfoId();

		// when
		int newMin = 60;
		boolean result = exerciseInfoService.setExerciseMin(id, newMin);

		// then
		assertTrue(result);

		ExerciseInfos updated = exerciseInfoRepository.findById(id).orElseThrow();
		assertEquals(newMin, updated.getExerciseMin());

		float expectedKcal = dashboardRepository.getWeight(updated.getExerciseNoteId()) *
			updated.getMet() * newMin / 60f;
		assertEquals(expectedKcal, updated.getExerciseKcal(), 0.01f);
	}

	@Test
	void testGetExerciseInfoListYes() {
		Exercise exercise = Exercise.builder()
			.memberId(1)
			.exerciseDate("2025-05-01")  // 이 값으로 exercise_note_id가 유도되는 구조라면
			.build();

		// when
		List<Exercise> result = exerciseInfoService.getExerciseInfoList(exercise);

		// then
		assertNotNull(result);
		assertEquals(11, result.size());

		assertEquals("걷기", result.get(0).getExerciseName());
		assertEquals(30, result.get(0).getExerciseMin());

		assertEquals("달리기", result.get(1).getExerciseName());
		assertEquals(20, result.get(1).getExerciseMin());
	}

}

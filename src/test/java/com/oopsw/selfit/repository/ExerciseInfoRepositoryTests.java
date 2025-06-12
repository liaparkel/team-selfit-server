package com.oopsw.selfit.repository;

import static org.junit.jupiter.api.Assertions.*;

import java.util.List;
import java.util.Optional;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.transaction.annotation.Transactional;

import com.oopsw.selfit.domain.ExerciseInfos;

@Transactional
@SpringBootTest
class ExerciseInfoRepositoryTests {

	@Autowired
	private ExerciseInfoRepository exerciseInfoRepository;


	@Test
	public void removeExercise() {
		// given
		exerciseInfoRepository.deleteById(1);

		// when
		Optional<ExerciseInfos> e = exerciseInfoRepository.findById(1);

		// then
		assertFalse(e.isPresent());
	}

	@Test
	public void testRemoveExerciseNotFoundExerciseInfoId() {
		// given
		int nonExistId = 9999;

		// when & then
		assertThrows(IllegalArgumentException.class, () -> {
			if (!exerciseInfoRepository.existsById(nonExistId)) {
				throw new IllegalArgumentException("삭제할 운동 정보가 존재하지 않습니다.");
			}
			exerciseInfoRepository.deleteById(nonExistId);
		});
	}

	@Test
	public void testSetExerciseMinYes() {
		// given
		int exerciseInfoId = 1;

		ExerciseInfos exercise = exerciseInfoRepository.findById(exerciseInfoId)
			.orElseThrow(() -> new IllegalArgumentException("해당 exerciseInfoId는 존재하지 않음"));

		// when
		exercise.setExerciseMin(60); // 예: 운동 시간 60분으로 수정
		exerciseInfoRepository.save(exercise);

		// then
		assertEquals(60, exercise.getExerciseMin());
	}

	@Test
	void testSetExerciseMinNotFoundExerciseInfoId() {
		int nonExistId = 9999;

		assertThrows(IllegalArgumentException.class, () -> {
			ExerciseInfos exercise = exerciseInfoRepository.findById(nonExistId)
				.orElseThrow(() -> new IllegalArgumentException("해당 exerciseInfoId는 존재하지 않음"));


			exercise.setExerciseMin(60);
			exerciseInfoRepository.save(exercise);
		});
	}

	@Test
	public void addExercise() {
		// given

		ExerciseInfos exerciseInfo = ExerciseInfos.builder()
			.exerciseName("런닝머신")
			.exerciseMin(30)
			.met(4)
			.exerciseKcal(300)
			.exerciseNoteId(1)
			.build();
		ExerciseInfos saved = exerciseInfoRepository.save(exerciseInfo);

		// when
		int id = saved.getExerciseInfoId();

		// then
		assertNotEquals(0, id);
	}

	@Test
	public void testGetDetailYes() {
		// given
		int exerciseNoteId = 1;

		// when
		List<ExerciseInfos> exerciseList = exerciseInfoRepository.findByExerciseNoteId(exerciseNoteId);

		// then
		assertNotNull(exerciseList);
		assertFalse(exerciseList.isEmpty());
		for (ExerciseInfos exercise : exerciseList) {
			assertEquals(exerciseNoteId, exercise.getExerciseNoteId()); // 전부 해당 exerciseNoteId와 매칭되는지
		}
	}

	@Test
	public void testGetDetailNotFoundNoteId() {
		// given
		int nonExistExerciseNoteId = 99999;

		// when
		List<ExerciseInfos> exerciseList = exerciseInfoRepository.findByExerciseNoteId(nonExistExerciseNoteId);

		// then
		assertNotNull(exerciseList);
		assertTrue(exerciseList.isEmpty());
	}

}



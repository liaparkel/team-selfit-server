package com.oopsw.selfit.service;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import org.springframework.stereotype.Service;

import com.oopsw.selfit.domain.ExerciseInfos;
import com.oopsw.selfit.dto.Exercise;
import com.oopsw.selfit.repository.DashboardRepository;
import com.oopsw.selfit.repository.ExerciseInfoRepository;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class ExerciseInfoService {
	private final ExerciseInfoRepository exerciseInfoRepository;
	private final DashboardRepository dashboardRepository;

	public boolean removeExercise(int exerciseInfoId) {
		if (exerciseInfoRepository.existsById(exerciseInfoId)) {
			exerciseInfoRepository.deleteById(exerciseInfoId);
			return true;
		}
		return false;
	}

	public boolean addExerciseInfo(Exercise exercise) {
		// 소모 칼로리 계산
		float kcal = dashboardRepository.getWeight(exercise.getExerciseNoteId()) *
			exercise.getMet() *
			exercise.getExerciseMin() / 60f;

		// DTO → Entity 수동 변환
		ExerciseInfos entity = ExerciseInfos.builder()
			.exerciseNoteId(exercise.getExerciseNoteId())
			.exerciseMin(exercise.getExerciseMin())
			.exerciseKcal(kcal)
			.exerciseName(exercise.getExerciseName())
			.met(exercise.getMet())
			.build();

		// JPA 저장
		exerciseInfoRepository.save(entity);
		return true;
	}

	public boolean setExerciseMin(int exerciseInfoId, int newMin) {
		Optional<ExerciseInfos> exerciseInfos = exerciseInfoRepository.findById(exerciseInfoId);
		if (exerciseInfos.isEmpty()) {
			return false; // 존재하지 않음
		}

		ExerciseInfos exercise = exerciseInfos.get();

		exercise.setExerciseMin(newMin);

		float weight = dashboardRepository.getWeight(exercise.getExerciseNoteId()); // member weight
		float met = exercise.getMet();
		float kcal = weight * met * newMin / 60f;

		exercise.setExerciseKcal(kcal);
		exerciseInfoRepository.save(exercise);
		return true;
	}

	public List<Exercise> getExerciseInfoList(Exercise exercise) {
		int exerciseInfoId = dashboardRepository.getExerciseNoteId(exercise);
		List<ExerciseInfos> list = exerciseInfoRepository.findByExerciseNoteId(exerciseInfoId);

		List<Exercise> exerciseList = new ArrayList<>();
		for (ExerciseInfos exerciseInfos : list) {
			Exercise dto = Exercise.builder()
				.exerciseInfoId(exerciseInfos.getExerciseInfoId())
				.exerciseNoteId(exerciseInfos.getExerciseNoteId())
				.exerciseName(exerciseInfos.getExerciseName())
				.exerciseMin(exerciseInfos.getExerciseMin())
				.exerciseKcal((int)exerciseInfos.getExerciseKcal())
				.build();
			exerciseList.add(dto);
		}
		return exerciseList;
	}


}




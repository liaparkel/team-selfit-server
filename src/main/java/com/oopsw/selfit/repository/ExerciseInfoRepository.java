package com.oopsw.selfit.repository;


import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;

import com.oopsw.selfit.domain.ExerciseInfos;

public interface ExerciseInfoRepository extends JpaRepository<ExerciseInfos, Integer> {
	List<ExerciseInfos> findByExerciseNoteId(int exerciseNoteId);
}

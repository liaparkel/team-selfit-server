package com.oopsw.selfit.repository;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.ibatis.annotations.Mapper;

import com.oopsw.selfit.dto.Checklist;
import com.oopsw.selfit.dto.Exercise;
import com.oopsw.selfit.dto.Food;
import com.oopsw.selfit.dto.Member;

@Mapper
public interface DashboardRepository {

	Member getBmr(int memberId);

	Food getIntakeKcal(Food food);

	Exercise getExerciseKcal(Exercise exercise);

	List<Food> getYearIntakeKcal(HashMap<String, Object> map);

	List<Exercise> getYearExerciseKcal(HashMap<String, Object> map);

	int addFoodList(Food food);

	int removeFoodList(Food food);

	int addExerciseList(Exercise exercise);

	int removeExerciseList(Exercise exercise);

	List<Checklist> getCheckList(Checklist checklist);

	int addChecklist(Checklist checklist);

	int removeChecklist(int checklistId);

	String getGoal(int memberId);

	List<Map<String, Object>> getYearExerciseAvgAll(Map<String, Object> param);

	List<Map<String, Object>> getYearIntakeAvgAll(Map<String, Object> param);

	int isChecklist(int memberId, String checkDate);

	int isFoodNote(int memberId, String intakeDate);

	int isExerciseNote(int memberId, String exerciseDate);

	int getMet(int exerciseId);

	int getWeight(int exerciseNoteId);

	Integer getFoodNoteId(Food food);

	Integer getExerciseNoteId(Exercise exercise);
}

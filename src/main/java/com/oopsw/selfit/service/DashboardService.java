package com.oopsw.selfit.service;

import java.time.LocalDate;
import java.time.Period;
import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.oopsw.selfit.dto.Checklist;
import com.oopsw.selfit.dto.Exercise;
import com.oopsw.selfit.dto.Food;
import com.oopsw.selfit.dto.Member;
import com.oopsw.selfit.repository.DashboardRepository;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@Service
public class DashboardService {
	private final DashboardRepository dashboardRepository;

	public void isAlreadyExists(int exists, String type, String date) {
		if (exists > 0) {
			throw new IllegalStateException("이미 해당 날짜에 " + type + "이(가) 존재합니다: " + date);
		}
	}


	public int getBmr(int memberId) {
		Member member = dashboardRepository.getBmr(memberId);

		int age = getAge(member.getBirthday());
		int bmr = -1;
		switch (member.getGender()) {
			case "남자":
				bmr = (int)((10 * member.getWeight()) + (6.25 * member.getHeight()) - (5 * age) + 5);
				break;
			case "여자":
				bmr = (int)((10 * member.getWeight()) + (6.25 * member.getHeight()) - (5 * age) - 161);
				break;
			default:
				throw new IllegalArgumentException("잘못된 성별입니다: " + member.getGender());
		}
		return bmr;
	}

	public int getAge(String birthday) {
		LocalDate birthDate = LocalDate.parse(birthday, DateTimeFormatter.ofPattern("yyyy-MM-dd"));
		LocalDate today = LocalDate.now();

		// Period로 만 나이 계산
		return Period.between(birthDate, today).getYears();
	}

	public Food getIntakeKcal(Food food) {
		return dashboardRepository.getIntakeKcal(food);
	}

	public Exercise getExerciseKcal(Exercise exercise) {
		return dashboardRepository.getExerciseKcal(exercise);
	}

	public List<Food> getYearIntakeKcal(HashMap<String, Object> map) {
		return dashboardRepository.getYearIntakeKcal(map);
	}

	public List<Exercise> getYearExerciseKcal(HashMap<String, Object> map) {
		return dashboardRepository.getYearExerciseKcal(map);
	}

	@Transactional
	public int addFoodList(Food food) {
		int cnt = dashboardRepository.isFoodNote(food.getMemberId(), food.getIntakeDate());
		if (cnt > 0) {
			Integer existId = dashboardRepository.getFoodNoteId(food);
			return existId;
		}

		dashboardRepository.addFoodList(food);
		return food.getFoodNoteId();
	}

	public boolean removeFoodList(Food food) {
		return dashboardRepository.removeFoodList(food) > 0;
	}

	public int addExerciseList(Exercise exercise) {
		// 1) 먼저, 해당 memberId + exerciseDate 조합으로 이미 노트가 있는지 조회
		Integer existingNoteId = dashboardRepository.getExerciseNoteId(Exercise.builder().memberId(
			exercise.getMemberId()).exerciseDate(exercise.getExerciseDate()).build());
		if (existingNoteId != null && existingNoteId > 0) {
			// 이미 노트가 있다면 예외를 던지지 않고, 그냥 그 ID를 바로 반환
			return existingNoteId;
		}

		// 2) 노트가 없으면 새로 insert
		dashboardRepository.addExerciseList(exercise);
		return exercise.getExerciseNoteId();  // (useGeneratedKeys로 PK가 채워진 상태)
	}

	public boolean removeExerciseList(Exercise exercise) {
		return dashboardRepository.removeExerciseList(exercise) > 0;
	}

	public List<Checklist> getCheckList(Checklist checklist) {
		return dashboardRepository.getCheckList(checklist);
	}


	public int addChecklist(Checklist checklist) {
		int exists = dashboardRepository.isChecklist(checklist.getMemberId(), checklist.getCheckDate());
		isAlreadyExists(exists, "체크리스트", checklist.getCheckDate());

		dashboardRepository.addChecklist(checklist);
		return checklist.getChecklistId();
	}

	public boolean removeChecklist(int checklistId) {
		return dashboardRepository.removeChecklist(checklistId) > 0;
	}


	public String getGoal(int memberId) {
		String goal = dashboardRepository.getGoal(memberId);
		if (goal == null) {
			throw new IllegalArgumentException("존재하지 않는 회원입니다: memberId = " + memberId);
		}
		return goal;
	}


	public List<Map<String, Object>> getYearExerciseAvgAll(int memberId, int exerciseYear) {
		Member member = dashboardRepository.getBmr(memberId);

		String birthday = member.getBirthday();
		int age = getAge(birthday);
		int height = (int)member.getHeight();
		int weight = (int)member.getWeight();

		int minAge = (age / 10) * 10;
		int maxAge = minAge + 9;

		int heightMin = (height / 10) * 10;
		int heightMax = heightMin + 9;

		int weightMin = (weight / 10) * 10;
		int weightMax = weightMin + 9;

		Map<String, Object> param = new HashMap<>();
		param.put("memberId", memberId);
		param.put("gender", member.getGender());
		param.put("minAge", minAge);
		param.put("maxAge", maxAge);
		param.put("heightMin", heightMin);
		param.put("heightMax", heightMax);
		param.put("weightMin", weightMin);
		param.put("weightMax", weightMax);
		param.put("exerciseYear", exerciseYear);

		return dashboardRepository.getYearExerciseAvgAll(param);
	}


	public List<Map<String, Object>> getYearIntakeAvgAll(int memberId, int intakeYear) {
		Member member = dashboardRepository.getBmr(memberId);

		String birthday = member.getBirthday();
		int age = getAge(birthday);
		int height = (int)member.getHeight();
		int weight = (int)member.getWeight();

		int minAge = (age / 10) * 10;
		int maxAge = minAge + 9;

		int heightMin = (height / 10) * 10;
		int heightMax = heightMin + 9;

		int weightMin = (weight / 10) * 10;
		int weightMax = weightMin + 9;

		Map<String, Object> param = new HashMap<>();
		param.put("memberId", memberId);
		param.put("gender", member.getGender());
		param.put("minAge", minAge);
		param.put("maxAge", maxAge);
		param.put("heightMin", heightMin);
		param.put("heightMax", heightMax);
		param.put("weightMin", weightMin);
		param.put("weightMax", weightMax);
		param.put("intakeYear", intakeYear);

		return dashboardRepository.getYearIntakeAvgAll(param);
	}

}

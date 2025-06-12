package com.oopsw.selfit.repository;

import static org.junit.jupiter.api.Assertions.*;

import java.util.List;
import java.util.Optional;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.transaction.annotation.Transactional;

import com.oopsw.selfit.domain.FoodInfos;

@Transactional
@SpringBootTest
public class FoodInfoRepositoryTests {
	@Autowired
	private FoodInfoRepository foodInfoRepository;
	@Test
	public void removeFood() {
		// given
		foodInfoRepository.deleteById(1);
		// when
		Optional<FoodInfos> f = foodInfoRepository.findById(1);
		// then
		assertFalse(f.isPresent());
	}

	@Test
	public void testRemoveFoodNotFoundFoodInfoId() {

		// given
		int nonExistId = 9999;

		// when & then
		assertThrows(IllegalArgumentException.class, () -> {
			if (!foodInfoRepository.existsById(nonExistId)) {
				throw new IllegalArgumentException("삭제할 음식 정보가 존재하지 않습니다.");
			}

			foodInfoRepository.deleteById(nonExistId);
		});
	}

	@Test
	public void testSetIntakeYes() {

		// given
		int foodInfoId = 1;

		FoodInfos food = foodInfoRepository.findById(foodInfoId)
			.orElseThrow(() -> new IllegalArgumentException("해당 foodInfoId는 존재하지 않음"));

		// when
		food.setIntake(100);
		foodInfoRepository.save(food);

		// then
		assertEquals(100, food.getIntake());
	}

	@Test
	void testSetIntakeNotFoundFoodInfoId() {
		// given
		int nonExistId = 9999;

		// when & then
		assertThrows(IllegalArgumentException.class, () -> {
			FoodInfos food = foodInfoRepository.findById(nonExistId)
				.orElseThrow(() -> new IllegalArgumentException("해당 foodInfoId는 존재하지 않음"));

			food.setIntake(100);
			foodInfoRepository.save(food);
		});
	}

	@Test
	public void addFood() {
		//given
		FoodInfos food = FoodInfos.builder()
			.foodName("아메리카노")
			.intake(100)
			.unitKcal(50)
			.intakeKcal(100)
			.foodNoteId(1)
			.build();
		FoodInfos saved = foodInfoRepository.save(food);

		//when
		int id = saved.getFoodInfoId();

		//then
		assertNotEquals(0, id);

	}

	@Test
	public void testGetDetailYes() {
		// given
		int foodNoteId = 1;

		// when
		List<FoodInfos> foodList = foodInfoRepository.findByFoodNoteId(foodNoteId);

		// then
		assertNotNull(foodList);
		assertFalse(foodList.isEmpty());
		for (FoodInfos food : foodList) {
			assertEquals(foodNoteId, food.getFoodNoteId()); // 전부 해당 foodNoteId와 매칭되는지
		}
		System.out.println(foodList);
	}

	@Test
	public void testGetDetailNotFoundNoteId() {
		// given
		int nonExistFoodNoteId = 99999;

		// when
		List<FoodInfos> foodList = foodInfoRepository.findByFoodNoteId(nonExistFoodNoteId);

		// then
		assertNotNull(foodList);
		assertTrue(foodList.isEmpty());
	}

}
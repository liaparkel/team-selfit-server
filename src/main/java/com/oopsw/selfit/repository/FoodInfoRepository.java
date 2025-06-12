package com.oopsw.selfit.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;

import com.oopsw.selfit.domain.FoodInfos;

public interface FoodInfoRepository extends JpaRepository<FoodInfos, Integer> {
	List<FoodInfos> findByFoodNoteId(int foodNoteId);
}

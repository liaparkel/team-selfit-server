package com.oopsw.selfit.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.oopsw.selfit.domain.CheckItem;

public interface CheckRepository extends JpaRepository<CheckItem, Long> {
	int countByChecklistId(Long checklistId);
}

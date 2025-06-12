package com.oopsw.selfit.service;

import java.util.Optional;

import org.springframework.stereotype.Service;

import com.oopsw.selfit.domain.CheckItem;
import com.oopsw.selfit.dto.Checklist;
import com.oopsw.selfit.repository.CheckRepository;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@Service
public class CheckService {

	private final CheckRepository checkRepository;

	public boolean addCheckItem(Checklist checklist) {
		int count = checkRepository.countByChecklistId((long)checklist.getChecklistId());

		if (count >= 5) {
			throw new IllegalStateException("체크리스트 항목은 최대 5개까지만 등록할 수 있습니다.");
		}

		CheckItem checkItem = CheckItem.builder()
			.checkContent(checklist.getCheckContent())
			.isCheck(false)
			.checklistId((long)checklist.getChecklistId())
			.build();

		checkRepository.save(checkItem);
		return true;
	}

	public boolean removeCheckItem(Checklist checklist) {
		// Optional<T>는 값이 있을 수도 없을 수도 있는 컨테이너 객체
		// 	T가 null일 수도 있으니, 직접 null 체크하지 말고 Optional로 감싸서 안전하게 써라는 의미
		Optional<CheckItem> checkItem = checkRepository.findById((long)checklist.getCheckId());

		// Optional에서 제공하는 주요 메서드
		// isPresent() → 값이 있으면 true
		// isEmpty() → 값이 없으면 true (Java 11 이상)
		// orElse(), orElseThrow() → 값이 없을 때 대처 방식
		if (checkItem.isEmpty()) {
			throw new IllegalArgumentException("존재하지 않는 체크 항목");
		}
		checkRepository.deleteById((long)checklist.getCheckId());
		return true;
	}

	public boolean setCheckItem(Checklist checklist) {
		Optional<CheckItem> checkItem = checkRepository.findById((long)checklist.getCheckId());

		if (checkItem.isEmpty()) {
			throw new IllegalArgumentException("수정할 체크 항목이 존재하지 않습니다.");
		}
		CheckItem item = checkItem.get();
		item.setCheckContent(checklist.getCheckContent());

		checkRepository.save(item);
		return true;
	}

	public boolean setIsCheckItem(Checklist checklist) {
		Optional<CheckItem> checkItem = checkRepository.findById((long)checklist.getCheckId());

		if (checkItem.isEmpty()) {
			throw new IllegalArgumentException("존재하지 않는 체크 항목입니다.");
		}

		CheckItem item = checkItem.get();
		item.setIsCheck(!item.getIsCheck());

		checkRepository.save(item);

		return true;
	}
}

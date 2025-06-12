package com.oopsw.selfit.repository;

import static org.junit.jupiter.api.Assertions.*;

import java.util.Optional;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.transaction.annotation.Transactional;

import com.oopsw.selfit.domain.CheckItem;

@Transactional
@SpringBootTest
public class CheckRepositoryTests {

	@Autowired
	private CheckRepository checkRepository;

	private CheckItem testItem;

	@BeforeEach
	void setUp() {
		testItem = checkRepository.save(CheckItem.builder()
			.checkContent("기본 항목")
			.isCheck(false)
			.checklistId(1L)  // 반드시 존재하는 checklistId
			.build());
	}

	// ✅ Check_Item 등록 테스트
	@Test
	public void testAddCheckItemYes() {
		CheckItem item = CheckItem.builder()
			.checkContent("창훈이 10kg 빼기")
			.isCheck(false)
			.checklistId(1L)
			.build();

		CheckItem saved = checkRepository.save(item);

		assertNotNull(saved.getCheckId(), "저장 후 ID가 null이 아니어야 한다");
		assertEquals("창훈이 10kg 빼기", saved.getCheckContent());
	}

	// ✅ Check_Item 삭제 테스트
	@Test
	public void testRemoveCheckItemYes() {
		CheckItem item = checkRepository.save(CheckItem.builder()
			.checkContent("삭제 테스트 항목")
			.isCheck(false)
			.checklistId(1L)
			.build());
		Long checkId = item.getCheckId();

		checkRepository.deleteById(checkId);
		Optional<CheckItem> result = checkRepository.findById(checkId);

		assertFalse(result.isPresent(), "삭제 후 해당 체크 항목은 없어야 한다");
	}

	@Test
	public void testRemoveCheckItemInvalid() {
		Long invalidCheckId = -1L;

		assertDoesNotThrow(() -> checkRepository.deleteById(invalidCheckId));
		Optional<CheckItem> result = checkRepository.findById(invalidCheckId);

		assertFalse(result.isPresent(), "존재하지 않는 ID를 삭제해도 예외는 없어야 한다");
	}

	// ✅ Check_Item 수정 테스트
	@Test
	public void testSetCheckItemYes() {
		Optional<CheckItem> itemOpt = checkRepository.findById(testItem.getCheckId());
		assertTrue(itemOpt.isPresent(), "수정할 체크 항목이 존재해야 함");

		CheckItem item = itemOpt.get();
		item.setCheckContent("수정");
		checkRepository.save(item);

		CheckItem updated = checkRepository.findById(item.getCheckId()).orElseThrow();
		assertEquals("수정", updated.getCheckContent(), "체크 내용이 '수정'으로 바뀌어야 함");
	}

	@Test
	public void testSetCheckItemInvalid() {
		Long invalidCheckId = -1L;
		Optional<CheckItem> itemOpt = checkRepository.findById(invalidCheckId);

		assertFalse(itemOpt.isPresent(), "존재하지 않는 체크 항목이어야 한다");
	}

	// ✅ Check_Item 상태 토글 테스트
	@Test
	public void testIsCheckItemYes() {
		Long checkId = testItem.getCheckId();

		Optional<CheckItem> itemOpt = checkRepository.findById(checkId);
		assertTrue(itemOpt.isPresent(), "체크 항목이 존재해야 함");

		CheckItem checkItem = itemOpt.get();
		Boolean oldStatus = checkItem.getIsCheck();

		checkItem.setIsCheck(!oldStatus);
		checkRepository.save(checkItem);

		CheckItem updated = checkRepository.findById(checkId).orElseThrow();
		assertEquals(!oldStatus, updated.getIsCheck());
	}

	@Test
	public void testIsCheckItemInvalid() {
		Long invalidCheckId = -1L;
		Optional<CheckItem> itemOpt = checkRepository.findById(invalidCheckId);

		assertFalse(itemOpt.isPresent(), "존재하지 않는 체크 항목이어야 함");
	}
}

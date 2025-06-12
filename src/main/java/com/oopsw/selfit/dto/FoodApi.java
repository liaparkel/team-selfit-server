package com.oopsw.selfit.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class FoodApi {
	private String foodCd; //식품코드
	private String foodNm; //식품명
	private String enerc; //단위당_칼로리
	private String foodSize; //식품총중량
}

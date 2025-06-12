package com.oopsw.selfit.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Entity
@Table(name = "FOOD_INFOS")
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class FoodInfos {
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name = "FOOD_INFO_ID")
	private int foodInfoId;

	@Column(name = "FOOD_NAME", nullable = false)
	private String foodName;

	@Column(name = "INTAKE", nullable = false)
	private int intake;

	@Column(name = "INTAKE_KCAL", nullable = false)
	private float intakeKcal;

	@Column(name = "UNIT_KCAL", nullable = false)
	private int unitKcal;

	@Column(name = "FOOD_NOTE_ID", nullable = false)
	private int foodNoteId;

}

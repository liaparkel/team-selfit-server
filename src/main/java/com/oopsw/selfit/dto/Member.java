package com.oopsw.selfit.dto;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.ToString;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
@ToString(exclude = {"pw"})
public class Member {
	private int memberId;
	private String email;
	private String pw;
	private String name;
	private String nickname;
	private String gender;
	private String birthday;
	private float height;
	private float weight;
	private String goal;
	private String joinDate;
	private String memberType;
	private String profileImg;
}

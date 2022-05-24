package com.prgrms.devcourse.user;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.Table;

import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.ToString;

@ToString
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Table(name = "users")
@Entity
public class User {

	@Id @GeneratedValue(strategy = GenerationType.AUTO)
	private Long id;

	private String loginId;
	private String passwd;

	@ManyToOne
	@JoinColumn(name = "group_id")
	Group group;

	public User(String loginId, String passwd) {
		this.loginId = loginId;
		this.passwd = passwd;
	}

	public void setGroup(Group group) {
		this.group = group;
	}
}

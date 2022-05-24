package com.prgrms.devcourse.user;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Table;

import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.ToString;

@ToString
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Table(name = "permissions")
@Entity
public class Permission {

	@Id @GeneratedValue(strategy = GenerationType.AUTO)
	private Long id;

	private String name;

	public Permission(String name) {
		this.name = name;
	}
}

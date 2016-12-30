package com.eventmanager.dao;

import javax.enterprise.context.RequestScoped;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.persistence.TypedQuery;
import javax.transaction.Transactional;

import com.eventmanager.model.User;

@RequestScoped
public class UserDao {

	@PersistenceContext(unitName = "event-manager")
	private EntityManager entityManager;

	@Transactional
	public User addUser(User user) {
		entityManager.persist(user);
		return user;
	}

	@Transactional
	public User findByUserName(String username) {

		TypedQuery<User> query = entityManager
				.createNamedQuery("findByUserName", User.class)
				.setParameter("userName", username);

		User result = query.getResultList().size() > 0 ? query.getResultList().get(0)
				: null;

		return result;
	}

}

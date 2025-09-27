package mz.ujc.secure_messaging_system.repository;


import mz.ujc.secure_messaging_system.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;
import java.util.List;
import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByUsername(String username);
    Optional<User> findByEmail(String email);
    boolean existsByUsername(String username);
    boolean existsByEmail(String email);
    
    @Query("SELECT u FROM User u WHERE u.isOnline = true AND u.id != :currentUserId")
    List<User> findOnlineUsers(Long currentUserId);
    
    @Query("SELECT u FROM User u WHERE u.id != :currentUserId ORDER BY u.username")
    List<User> findAllExceptCurrent(Long currentUserId);
}
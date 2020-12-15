SELECT helo_posts.id AS post_id, title, content, img, profile_pic, date_created, upvotes, username AS author_username FROM helo_posts
JOIN helo_users ON helo_users.id = helo_posts.author_id
WHERE lower(helo_posts.title) LIKE %$2 AND helo_posts.author_id != $1
ORDER BY date_created DESC;
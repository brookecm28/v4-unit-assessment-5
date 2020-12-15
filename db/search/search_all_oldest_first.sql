SELECT helo_posts.id AS post_id, title, content, img, profile_pic, date_created, username AS author_username FROM helo_posts
JOIN helo_users ON helo_users.id = helo_posts.author_id
WHERE lower(title) LIKE $1
ORDER BY date_created ASC;
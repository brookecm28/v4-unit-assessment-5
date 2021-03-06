const bcrypt = require('bcryptjs')

module.exports = ({
    register: async (req, res) => {
        const db = req.app.get('db')
        const {username, password, profile_pic} = req.body
        const [existingUser] = await db.user.find_user_by_username([username])

        if(existingUser) {
            return res.status(409).send('Username taken. Please choose a different username.')
        }
        
        const salt = bcrypt.genSaltSync(10)
        const hash = bcrypt.hashSync(password, salt)
        const newUser = await db.user.create_user([username, hash, profile_pic])

        req.session.user=newUser

        res.status(200).send(newUser)
    },
    login: async (req, res) => {
        const db = req.app.get('db')
        const {username, password} = req.body
        const existingUser = await db.user.find_user_by_username([username])
        const user = existingUser[0]

        if(!user) {
            return res.status(404).send('No account found with that username.')
        }

        const isAuthenticated = bcrypt.compareSync(password, user.password)

        if(!isAuthenticated) {
            return res.status*(403).send('Incorrect password.')
        }

        delete user.password
        
        req.session.user = {
            username: user.username,
            password: user.password,
            profile_pic: user.profile_pic,
            id: user.id
        }
        console.log(user)
        res.status(200).send(user)
    },
    logout: (req, res) => {
        const db = req.app.get('db')
        req.session.destroy()
        res.sendStatus(200)
    },
    getUser: (req, res) => {
        const db = req.app.get('db')
        if (req.session.user) {
            res.status(200).send(req.session.user)
        } else {
            res.status(404).send('No session found.')
        }
    }
})
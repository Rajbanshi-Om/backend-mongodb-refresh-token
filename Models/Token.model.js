
const mongoose = require('mongoose')

const TokenSchema = mongoose.Schema({
    token: {
        type: String,
        required: true,
        unique:true
    },
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User'
    }
})

const Token = mongoose.model('Token', TokenSchema)

module.exports = Token
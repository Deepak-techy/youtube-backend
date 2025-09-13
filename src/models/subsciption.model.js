import mongoose, { Schema } from "mongoose";

const subscriptionSchema = new Schema(
    {
        subscriber: {
            type: Schema.Types.ObjectId,    // user who is subscribing to a channel
            ref: "User"
        },
        channel: {
            type: Schema.Types.ObjectId,    // the owner of the channel who is also a user
            ref: "User"
        }
    },
    {
        timestamps: true
    }
)

export const Subscription = mongoose.model("Subscription", subscriptionSchema)
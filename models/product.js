import { Sequelize, DataTypes } from 'sequelize';

const sequelize = new Sequelize('sqlite::memory:');

const Product = sequelize.define('Product', {
    productName: DataTypes.STRING,
    productBrand: DataTypes.STRING,
    price: {
        type: DataTypes.FLOAT,
        validate: {
            isFloat: true,
            min: 0.01,
        },
    },
    description: DataTypes.TEXT,
    imageUrl: DataTypes.STRING,
    category: DataTypes.STRING,
    stock: {
        type: DataTypes.INTEGER,
        defaultValue: 0,
        validate: {
            min: 0,
        },
    },
    rating: {
        type:DataTypes.FLOAT,
        defaultValue: 0.0,
        validate: {
            min: 0.0,
            max: 5.0,
        },
    },
    createdAt: {
        type: DataTypes.DATE,
        defaultValue: Sequelize.NOW,
    },
    updatedAt: {
        type: DataTypes.DATE,
        defaultValue: Sequelize.NOW,
    },
});

module.exports = Product;
// =============================================================================
// FRAUD DETECTION SYSTEM — MongoDB Initialization
// Creates databases, collections with schema validation, and indexes.
// Runs on first container start.
// =============================================================================

// Switch to the fraud detection database
db = db.getSiblingDB('fraud_detection');

// =============================================================================
// TRANSACTIONS — Time-series collection for enriched transactions
// =============================================================================
try {
    db.createCollection('transactions', {
        timeseries: {
            timeField:   'timestamp',
            metaField:   'metadata',
            granularity: 'seconds'
        },
        expireAfterSeconds: 7776000  // 90 days retention
    });
    print('Created transactions time-series collection');
} catch (e) {
    if (e.codeName !== 'NamespaceExists') {
        print('Error creating transactions collection: ' + e.message);
    } else {
        print('transactions collection already exists');
    }
}

// Indexes for transactions
db.transactions.createIndex({ 'metadata.customer_id': 1, 'timestamp': -1 });
db.transactions.createIndex({ 'metadata.fraud_probability': -1 });
db.transactions.createIndex({ 'metadata.tx_hash': 1 }, { unique: true });
db.transactions.createIndex({ 'metadata.country_code': 1, 'timestamp': -1 });

// =============================================================================
// FEATURE CACHE — Precomputed feature vectors
// =============================================================================
try {
    db.createCollection('feature_cache', {
        validator: {
            $jsonSchema: {
                bsonType: 'object',
                required: ['customer_id', 'feature_vector', 'computed_at'],
                properties: {
                    customer_id:    { bsonType: 'string' },
                    feature_vector: { bsonType: 'object' },
                    computed_at:    { bsonType: 'date' },
                    version:        { bsonType: 'string' }
                }
            }
        }
    });
    print('Created feature_cache collection');
} catch (e) {
    if (e.codeName !== 'NamespaceExists') print('Error: ' + e.message);
}

db.feature_cache.createIndex({ customer_id: 1 }, { unique: true });
db.feature_cache.createIndex({ computed_at: 1 }, { expireAfterSeconds: 300 }); // 5-min TTL

// =============================================================================
// MODEL PREDICTIONS — Historical prediction log (for drift detection)
// =============================================================================
try {
    db.createCollection('model_predictions', {
        capped: false
    });
    print('Created model_predictions collection');
} catch (e) {
    if (e.codeName !== 'NamespaceExists') print('Error: ' + e.message);
}

db.model_predictions.createIndex({ tx_hash: 1 });
db.model_predictions.createIndex({ customer_id: 1, predicted_at: -1 });
db.model_predictions.createIndex({ model_version: 1, predicted_at: -1 });
db.model_predictions.createIndex({ fraud_probability: -1 });
db.model_predictions.createIndex({ predicted_at: 1 }, { expireAfterSeconds: 31536000 }); // 1 year

// =============================================================================
// GRAPH SNAPSHOTS — Transaction graph for GNN analysis
// =============================================================================
try {
    db.createCollection('graph_snapshots');
    print('Created graph_snapshots collection');
} catch (e) {
    if (e.codeName !== 'NamespaceExists') print('Error: ' + e.message);
}

db.graph_snapshots.createIndex({ snapshot_at: -1 });
db.graph_snapshots.createIndex({ node_id: 1 });

// =============================================================================
// BLOCKCHAIN EVENTS — Mirror of Fabric chaincode events for fast queries
// =============================================================================
try {
    db.createCollection('blockchain_events');
    print('Created blockchain_events collection');
} catch (e) {
    if (e.codeName !== 'NamespaceExists') print('Error: ' + e.message);
}

db.blockchain_events.createIndex({ channel: 1, block_number: -1 });
db.blockchain_events.createIndex({ event_name: 1, emitted_at: -1 });
db.blockchain_events.createIndex({ entity_id: 1 });

// =============================================================================
// Insert sample data for dev
// =============================================================================
db.transactions.insertMany([
    {
        metadata: {
            customer_id: 'kyc-001',
            tx_hash: 'tx:hash:mongo:001',
            fraud_probability: 0.92,
            risk_score: 95.0,
            merchant_category: 'crypto',
            country_code: 'NG',
            amount: 15000.00,
            currency: 'USD'
        },
        timestamp: new Date(),
        features: {
            velocity_1h: 5,
            cross_border: true,
            avg_amount_7d: 3000.0,
            deviation_score: 4.2,
            pagerank: 0.82
        }
    },
    {
        metadata: {
            customer_id: 'kyc-002',
            tx_hash: 'tx:hash:mongo:002',
            fraud_probability: 0.45,
            risk_score: 52.0,
            merchant_category: 'retail',
            country_code: 'US',
            amount: 250.00,
            currency: 'USD'
        },
        timestamp: new Date(Date.now() - 60000),
        features: {
            velocity_1h: 1,
            cross_border: false,
            avg_amount_7d: 200.0,
            deviation_score: 0.3,
            pagerank: 0.12
        }
    }
]);

print('MongoDB initialization complete');
print('Collections: transactions, feature_cache, model_predictions, graph_snapshots, blockchain_events');

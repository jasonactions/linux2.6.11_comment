/**
 * 将页加入管理区的活动链表头部并递增管理区描述符的nr_active字段
 */
static inline void
add_page_to_active_list(struct zone *zone, struct page *page)
{
	list_add(&page->lru, &zone->active_list);
	zone->nr_active++;
}

/**
 * 将页加入管理区的非活动链表头部并递增管理区描述符的nr_inactive字段
 */
static inline void
add_page_to_inactive_list(struct zone *zone, struct page *page)
{
	list_add(&page->lru, &zone->inactive_list);
	zone->nr_inactive++;
}

/**
 * 从管理区的活动链表中删除页并递减管理区描述符的nr_active
 */
static inline void
del_page_from_active_list(struct zone *zone, struct page *page)
{
	list_del(&page->lru);
	zone->nr_active--;
}

/**
 * 从管理区的非活动链表中删除页并递减管理区描述符的nr_active
 */
static inline void
del_page_from_inactive_list(struct zone *zone, struct page *page)
{
	list_del(&page->lru);
	zone->nr_inactive--;
}

/**
 * 检查页的PG_active标志，根据检查结果，设置相应的标志。
 * 并将页从lru链表中删除
 * 
 */
static inline void
del_page_from_lru(struct zone *zone, struct page *page)
{
	list_del(&page->lru);
	if (PageActive(page)) {
		ClearPageActive(page);
		zone->nr_active--;
	} else {
		zone->nr_inactive--;
	}
}
